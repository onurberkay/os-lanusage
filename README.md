# os-hostguard — OPNsense HostGuard eklentisi

Firewall'un arkasındaki sunucuları (müşteri VDS'leri) izler ve korur: sunuculara yönelik saldırıları
(reflection, flood, brute force, tarama; Suricata ve CrowdSec ile birlikte) tespit eder, istenen saldırı
türlerinin kaynaklarını engelleme koşullarıyla `virusprot` tablosuna ekler, pf state ve kural limitlerini,
engellenen trafiği ve her IP'nin hangi portu / servisi kullandığını **Reporting → HostGuard** menüsünde
grafik ve tablolarla gösterir.

Eski adı **os-lanusage**'dır (1.6'ya kadar). 1.7 ve sonraki sürümlerin kurulumu eskisini kaldırır, veritabanını ve ayarları taşır
(bkz. *Kurulum*).

## Ne yapar?

| Özellik | Açıklama |
|---|---|
| Kayıt | pf state tablosu (`pfctl -ss -v`) her *N* saniyede okunur. Her bağlantı LAN IP'sine göre **inbound** (host'un sunduğu port, ör. dışarıdan 22'ye gelen SSH) ve **outbound** (host'un dışarıda bağlandığı port, ör. 443) olarak kaydedilir. |
| Dashboard | Zaman grafiği (bağlantı / trafik), en çok kullanılan inbound/outbound portlar, en aktif hostlar, tespit edilen servis dağılımı, KPI kutuları. 1s / 6s / 24s / 7g / 30g aralık, IP filtresi. |
| Tablolar | Hosts, Ports, Connections (kim kiminle hangi portta), Services. Hepsi aranabilir ve sıralanabilir. |
| Servis testi | Bir LAN host'unun bir portu sunduğu görüldüğünde firewall o porta bağlanıp servisi tanır: banner (SSH, FTP, SMTP, POP3, IMAP, MySQL/MariaDB, VNC, rsync, telnet), HTTP (Server başlığı, Proxmox/cPanel/Webmin/Plesk tanıma), TLS (sürüm + sertifika CN/SAN/bitiş tarihi), Redis, PostgreSQL, RDP, memcached, DNS (version.bind), NTP. İsteğe bağlı `nmap -sV`. Testler panelden elle de başlatılabilir (🩺 düğmesi / port rozetine tıklama). |

| LAN ↔ LAN | Bir LAN host'unun başka bir LAN host'una yaptığı her bağlantı ayrıca kaydedilir (cevapsız denemeler dahil) ve **LAN ↔ LAN** sekmesinde gösterilir. Kurallarca engellenen denemeler örneklemeyle bulunur, log gerekmez. Connections tablosunda bu satırlar `LAN↔LAN` rozetiyle işaretlenir. |
| Tarama tespiti | Bir LAN host'u 5 dakika içinde ≥10 farklı LAN host'una veya ≥20 farklı host/port'a dokunursa **kritik** uyarı (tarama / solucan). |
| MAC / IP takibi | ARP/NDP tablosundan MAC↔IP eşleşmeleri tutulur. Uyarılar: bir MAC'in birden fazla IPv4 kullanması (*Multiple IPs on one MAC*), MAC'in IP'sinin gün içinde değişmesi (*IP changed*), bir IP'nin başka bir MAC'e geçmesi (*IP moved to another MAC*: IP gaspı, ARP spoofing, IP çakışması; ileri geri 3 kez geçerse **kritik**). |
| Alerts | Tüm uyarılar önem derecesiyle tek listede, onaylanabilir (acknowledge). Overview'da açık uyarı şeridi, menüde **Reporting → HostGuard → Alerts** kısayolu. Yeni uyarılar syslog'a da `ALERT [...]` satırı olarak yazılır. |

| States / Limits | pf state tablosu doluluğu, limit sayaçları (`memory`, `state-limit`, `src-limit`, `max-src-conn(-rate)`, `overload table insertion`, `synfloods detected`, NAT `map-failed` …), "max states" sınırına yaklaşan kurallar, LAN host başına state sayısı ve saniyedeki yeni bağlantı. virusprot / sshlockout / CrowdSec tablolarına düşen LAN hostları. Menüde **Reporting → HostGuard → States / Limits**. |

### Engellenen trafik (log açmadan)

Block kuralları loglamıyorsa (saldırıda log patlamasın diye) engellenen trafik iki yoldan görülür:

1. **Örnekleme (host bazında, tahmini):** Her poll'da seçili arayüzler en fazla *Sample time* (5 sn) boyunca ya da
   *Sample packet cap* (20 000 paket) dolana kadar dinlenir. Sadece bağlantı denemeleri alınır: TCP SYN, UDP, ICMP echo.
   BPF paketi pf'den önce gördüğü için denemenin ardından pf state'i oluşmadıysa deneme **engellenmiştir**.
   Örnek sayısı dinleme süresine göre poll aralığına ölçeklenir.
   - Yük saldırının büyüklüğünden bağımsız ve sabittir: 1 Mpps flood'da da en fazla 20 000 paket işlenir.
   - Diske log yazılmaz, sadece toplanmış istatistik tutulur. Çok kaynaklı saldırıda host/port başına en çok gelen 20 kaynak
     ayrı, kalanı `others (N)` olarak saklanır.
   - Bridge modunda varsayılan olarak bridge'in tüm üyeleri dinlenir; dışarıdan gelen saldırılar upstream üyesinde görünür.
   - 1.7'den itibaren yalnız arayüze **giren** paketler alınır (`tcpdump -Q in`). Firewall'dan çıkan bir paket pf'yi
     zaten geçmiştir; önceki sürümlerde sunucunun dışarıya giden paketi upstream üyesinde (ör. WAN) yakalanıp yanlışlıkla
     "engellendi" görünebiliyordu. Yön filtresini desteklemeyen bir arayüzde eski yönteme dönülür ve Ayarlar sayfasındaki
     durum satırında belirtilir.
2. **Block kuralı sayaçları (kesin):** Her poll'da `pfctl -vvsr` ile block kurallarının paket sayaçları okunur. Kural başına
   anlık paket/sn ve dönem toplamı gösterilir. Açıklamalar `/tmp/rules.debug`'dan alınır. Host bilgisi vermez ama kesin değerdir.

**Nerede bakılıyor:** Yön adrese göre belirlenir: hedef müşteri ağınızdaysa "in", kaynak müşteri ağınızdaysa "out".
Transparent bridge'de varsayılan olarak bridge'in tüm üyeleri dinlenir. İnternetten gelen ve engellenen bir paket,
pf'in onu düşürdüğü **WAN (upstream) üyesinde** görülür. Her engellenen denemede hangi arayüzde görüldüğü
OPNsense'teki adıyla yazar, ör. `igb0 (WAN)`.

**Neden engellendi (log olmadan):** Her engellenen deneme sırayla şunlarla eşleştirilir:

1. Block kurallarının kullandığı pf tabloları (CrowdSec, virusprot, bogons, alias'lar): `<tablo> rule @N açıklama`
2. Kaynak başına limit (max-src-states / max-src-conn / max-src-conn-rate): `... limit rule @N açıklama`
3. Shaper o IP için paket düşürüyorsa: `shaper pipe N "açıklama" rate limit drops`
4. Kaynak limite %95+ yakınsa: `near ... limit rule @N (likely)`; bir kuralın `max` sınırı doluysa ve pf sayacı arttıysa: `rule @N max states full (likely)`
5. O anda dolu state tablosu (pf `memory` sayacı artmışsa)
6. Dışarıdan gelen özel/bogon kaynak adresi
7. Hiçbiri değilse: `no pass rule (default deny or a block rule)`. Hangi block kuralının durdurduğu log olmadan bilinemez;
   kesin sayılar Block rules tablosundadır.

Blocked sekmesinde sebep dağılımı grafiği, host başına ilk 3 sebep ve her denemenin sebebi gösterilir. Uyarılarda da "why:" olarak yazar.

Uyarılar:

| Tür | Varsayılan eşik | Anlamı |
|---|---|---|
| Blocked outbound (host) | ≥ 20 pkt/s | Müşteri VDS'i engellenen trafik gönderiyor (spam, tarama, ele geçirilmiş). Uyarıda en çok engellenen portlar ve hedef sayısı yazar. |
| Blocked attack (host) | ≥ 500 pkt/s, 10 katında critical | Bir VDS'e gelen saldırı engelleniyor. Uyarıda kaynak sayısı ve portlar yazar. |
| Block rule busy | ≥ 2000 pkt/s | Bir block kuralı yoğun çalışıyor |
| LAN → LAN connection / scan | | Engellenen LAN↔LAN denemeleri de örneklemeden gelir |

Sınırlar: Değerler tahmindir. pf'in state oluşturmadan geçirdiği trafik (`no state` kuralları) engellenmiş gibi görünür.
Routed + NAT kurulumunda WAN'da örneklenen NAT'lı adresler LAN ağına girmediği için zaten sayılmaz.

### State / limit uyarıları

| Tür | Önem | Ne zaman |
|---|---|---|
| State table filling up | high, %95'te critical | pf state tablosu ayardaki yüzdeyi (varsayılan %80) aştığında |
| pf limit reached | sayaca göre (memory ve synflood: critical) | Bir limit sayacı iki okuma arasında arttığında. Uyarıda o an en çok state tutan ve en hızlı bağlantı açan LAN hostları yazar. |
| Rule near max states | high, dolunca critical | "max states" tanımlı bir kural %90 dolduğunda |
| Many states (host, warning threshold) | high, 2 katında critical | Bir LAN host'u ≥ *Warning threshold: states per LAN host* (varsayılan 10 000) state tuttuğunda. Bu eklentinin uyarı eşiğidir, pf limiti değildir; hiçbir şeyi düşürmez. Ağırlıklı inbound ise "DDoS hedefi olabilir", outbound ise "flood / ele geçirilmiş olabilir" diye yazar. |
| Connection rate (host) | high | Bir LAN host'u saniyede ≥ 300 yeni bağlantı açtığında / aldığında |
| LAN host in block table | virusprot/sshlockout: high, CrowdSec: critical | Bir LAN IP'si izlenen bir pf tablosuna eklendiğinde |
| Source at rule limit | LAN kaynağı: high, dış kaynak: medium | Bir kaynak IP, kuralındaki `max-src-states`, `max-src-conn` ya da `max-src-conn-rate` sınırına ulaştığında. `pfctl -sS -v` (source tracking) okunur; uyarıda IP, limit (değer/sınır) ve kural (numara + açıklama) yazar. `src-limit` / `max-src-*` sayaç uyarıları da artık tahmin yerine o an limitte olan kaynakları yazar. %90'ı geçen kaynaklar States / Limits sekmesinde listelenir. |

### Kural limitleri ve doluluk

Her kuraldaki limitler `pfctl -vvsr` çıktısından otomatik okunur ve doluluk oranı hesaplanır:

| Limit | Neye göre | Doluluk |
|---|---|---|
| `max` | Kuralın toplam state'i | state / max |
| `max-src-nodes` | Kuraldaki kaynak adres sayısı (yalnız `source-track rule`) | kaynak sayısı / limit |
| `max-src-states` | Kaynak başına state | en yoğun kaynak / limit |
| `max-src-conn` | Kaynak başına kurulmuş TCP bağlantısı | en yoğun kaynak / limit |
| `max-src-conn-rate` | Kaynak başına yeni bağlantı hızı | en yoğun kaynak / limit |

OPNsense bu limitleri `source-track` yazmadan oluşturur. Bu durumda pf **global** kaynak takibi kullanır: her adres için
tek sayaç vardır, kaynak başına limiti olan tüm kurallar bunu paylaşır ve `pfctl -sS` kural numarası yazmaz. Eklenti
bu düğümleri limiti olan her kuralla karşılaştırır ve en sıkı sınırı raporlar. `source-track rule` olan kurallar
kendi düğümleriyle eşleşir. Tablo, %80'i geçen kaynak sayısını da gösterir.

**Yön (gelen mi, giden mi?)** pf'de "kaynak" her zaman bağlantıyı açan taraftır. Eklenti her kuralın
`from` / `to` adreslerinden, arayüzünden ve yönünden kimin bağlantılarını saydığını çıkarır:

| Gösterim | Anlamı |
|---|---|
| `→ in (clients)` | Kaynaklar dışarıda: internetten sunucularınıza bağlantı açan istemciler sayılır. Limite takılan dış IP'dir, sunucunuz değil. |
| `← out (your hosts)` | Kaynaklar LAN hostlarınız: sunucunuzun dışarıya açtığı bağlantılar sayılır. Limite takılan sizin sunucunuzdur, kendi yeni bağlantıları düşer. |
| `LAN ↔ LAN` | İki taraf da LAN'da. |
| `?` | Kuraldan anlaşılamadı (ör. floating `any → any`); her iki taraf için de kontrol edilir. |

Global takipte bir LAN hostunun sayacı artık yalnız giden kurallarla, dış bir IP'nin sayacı yalnız gelen kurallarla
karşılaştırılır.

**Host başına limit yoktur.** pf'de bir host iki şeyle sınırlanır: toplam state tablosu (herkes paylaşır) ve kendi
açtığı bağlantıların geçtiği kuralların kaynak başına limitleri. States / Limits sekmesindeki host tablosu bu ikisini ve
eklentinin uyarı eşiğini ayrı sütunlarda gösterir.

### Sunucularınıza yönelik saldırılar (Attacks sekmesi)

Ek bir dinleme yapılmaz; engellenen trafik için zaten alınan örnekler kullanılır. Bir LAN hostuna dışarıdan gelen
denemeler (engellenen ve geçen birlikte) *Attack threshold* değerini (varsayılan 50 pkt/s) aştığında bir **saldırı
olayı** açılır. Olay 10 dakika sessiz kalınca biter. Her olay için başlangıç, bitiş, en yüksek hız, kaynak sayısı,
portlar ve **firewall'dan geçen oran** tutulur. Geçen oran %50'yi aşarsa saldırı hosta ulaşıyordur ve uyarı critical olur.
Bir host için aynı anda tek olay açılır; türü en yoğun poll'daki türdür. Hostun kendi açtığı akışlara gelen yanıtlar
(DNS, QUIC, oyun trafiği) saldırı sayılmaz.

| Tür | Nasıl anlaşılır |
|---|---|
| Reflection / amplification | Paketlerin yarısından fazlası DNS (53), NTP (123), memcached (11211), SSDP (1900), CLDAP (389), SNMP (161) gibi kaynak portlarından gelen UDP yanıtları |
| Port scan | Paketlerin çoğu tek kaynaktan ve 20'den fazla porta |
| Distributed brute force | 10'dan fazla kaynaktan, ağırlıkla tek bir giriş portuna (22, 3389, 445, 21, 25, 3306 ...). Eşiğin beşte biri yeterlidir. |
| SYN / UDP / ICMP flood | Trafiğin %60'ından fazlası o protokol |

Aynı sekmede:
- **Suricata:** `/var/log/suricata/eve.json` her poll'da yalnız yeni eklenen kısmıyla okunur (poll başına en fazla 8 MB).
  Hedefi LAN hostu, kaynağı dışarısı olan alarmlar host ve imza bazında toplanır. Severity 1 alarmlar uyarı üretir.
  Suricata'da EVE log'unun açık olması gerekir.
- **CrowdSec:** 5 dakikada bir `cscli decisions list -o json` ile yerel kararlar okunur. Her dış kaynak için senaryo
  (ör. `crowdsecurity/ssh-bf`) gösterilir.
- **Dış kaynaklar:** Saldırılarda binlerce IP olabilir. Blocked ve States / Limits sekmelerinde dış IP'ler host/port ya
  da kural/limit başına tek satırda toplanır; hepsi tek tek bu sekmede listelenir.
- **Ağ türü ve sahibi:** Her dış kaynağın sahibi (AS numarası, adı, ülkesi) ve ağ türü gösterilir: *Cloud*, *CDN*,
  *VPN*, *Hosting / datacenter*, *Online service*; adres listelerinde yoksa AS kategorisi: *ISP (home, mobile)*,
  *Business*, *Education / research*, *Government* (kesik çerçeve ve `~` ile, tahmin olduğu belli). Ayrıca rol:
  *Tor exit*, *Crawler* (Googlebot, Bingbot, GPTBot, ClaudeBot ...), *Monitoring* (UptimeRobot, Pingdom ...),
  *Private Relay* (iCloud). Üstteki özet, listelenen kaynakları türe göre hem adres sayısıyla hem paket sayısıyla ve
  en çok kaynak gelen AS'leri gösterir; bir türe, role ya da AS'ye tıklayınca tablo onlara süzülür (arama kutusunda
  `kind:hosting`, `role:tor`, tam olarak bir AS için `as:16276;` gibi de yazılabilir). Spamhaus ASN-DROP'taki (suç amaçlı işletilen) ağlar
  ayrıca işaretlenir. Taramalar ve brute force çoğunlukla hosting / cloud ağlarından gelir; SYN / UDP / ICMP
  flood'larda kaynak adresler genelde sahtedir, sahipleri bir şey söylemez.

#### Ağ türü verisi (ücretsiz, üyelik gerektirmez)

Listeler günde bir kez indirilir (GitHub dosyaları sıkıştırılmış gelir, toplam ~15 MB) ve
`/var/db/hostguard/ipdata.db` içinde (yaklaşık 35 MB) yerel bir SQLite veritabanına yazılır; sorgular yereldir,
hiçbir adres dışarı gönderilmez. İlk indirme servis başladıktan bir dakika sonra yapılır, Attacks sekmesindeki
**update now** ile hemen başlatılabilir (Settings yetkisi gerekir). İndirilemeyen bir liste bir önceki günün verisiyle
kalır ve üç saat sonra bir kez daha denenir (yine olmazsa ertesi günkü indirmede); hiçbir liste gelmezse (WAN kapalı)
eski veri olduğu gibi kalır ve saatte bir denenir. Ayarlarda kapatılabilir (*Owner and network type of sources*); *Also hosting* alanına hosting olarak
sayılacak AS'ler yazılabilir (ör. `AS16276,AS24940`).

Listeler çakıştığında **güvenilir olan kazanır**; aynı güven katmanında daha dar (daha özel) ağ:

| Katman | Kaynak | Ne verir | Lisans |
|---|---|---|---|
| 1 resmi, doğrudan | AWS, Google Cloud, Oracle Cloud, DigitalOcean, Linode, Cloudflare, Fastly; [Tor Project](https://check.torproject.org/torbulkexitlist) | sağlayıcıların kendi yayımladığı aralıklar (*Cloud*, *CDN*), Tor çıkışları | herkese açık resmi listeler |
| 2 resmi, aktarılmış | [rezmoss/cloud-provider-ip-addresses](https://github.com/rezmoss/cloud-provider-ip-addresses) içindeki resmi listeler | Azure, Vultr, CDN'ler, SaaS, arama motoru / yapay zekâ botları, izleme servisleri, iCloud Private Relay, Mullvad | CC0 |
| 3 AS'den türetilmiş | [X4BNet lists_vpn](https://github.com/X4BNet/lists_vpn); rezmoss'ta resmi listesi olmayanlar (Hetzner, OVH, Contabo, Akamai ...) | hosting / datacenter ve VPN aralıkları | MIT (veri IPLocate.io, CC BY-SA 4.0); CC0 |
| AS: ayar | *Also hosting* | sizin hosting dediğiniz AS'ler | – |
| AS: tahmin | [ipverse/as-metadata](https://github.com/ipverse/as-metadata) | her AS için ISP / business / hosting / education / government | CC0 |
| sahip | [iptoasn.com](https://iptoasn.com/) | IP aralığı → AS numarası, adı, ülkesi (BGP) | PDDL (kamu malı) |
| işaret | [Spamhaus ASN-DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | suç amaçlı işletilen AS'ler | © The Spamhaus Project SLU, [kullanım şartları](https://www.spamhaus.org/drop/terms/) |

Roller (Tor, crawler, monitoring, Private Relay) ağ türünün yerine geçmez, yanında gösterilir: Amazonbot adresi hem
"Cloud · AWS" hem "Crawler"dır. rezmoss'ta henüz eşleştirilmemiş yeni bir sağlayıcı çıkarsa o atlanır (sessizce yanlış
türe girmesin diye).

Sınırlar: AS kategorisi tahmindir (ipverse de böyle belirtir); bir AS hem ev hem hosting hizmeti veriyorsa tek bir
kategori alır. Hosting listeleri AS bazlıdır; karışık sağlayıcılarda bazı ev adresleri hosting görünebilir.

### Engelleme koşulları (Block conditions sekmesi)

Koşullar sekmedeki **New condition** formuyla eklenir. Saldırı olayındaki, Suricata alarmındaki ya da kural limitine
takılan dış kaynaktaki **block** düğmesi bu formu doldurur; ban türü formda seçilip **Add condition** ile eklenir.
Bundan sonra her poll'da koşula uyan **dış** kaynaklar `virusprot` tablosuna eklenir; OPNsense bu tablodaki adresleri
engeller.

| Koşul (Match) | Neye uyar |
|---|---|
| Attack type | Attacks sekmesinin sınıflandırdığı saldırı türünün kaynakları (reflection, flood, brute force, port scan) |
| Alert Suricata dropped (IPS) | Suricata'nın kendisinin **drop** ettiği alarmlar (IPS modu, politikanızın drop'a çevirdiği kurallar): bir sid ya da boş bırakılırsa hepsi. IDS modunda hiçbir şey drop edilmez, koşul eşleşmez |
| Suricata signature (any action) | Bir sid'in bütün alarmları, yalnız loglananlar da |
| Source at a rule limit | Seçilen kuralın (ya da limiti olan herhangi bir kuralın) seçilen limitine (max source states / max established connections / max new connections rate) takılan dış kaynaklar. Kural listesi son poll'daki etiketli, kaynak limitli kurallardır; kuralın önce limite dolması beklenmez |

Hedef: belirli bir LAN hostu ya da boş = her host (kural limitinde hedef yoktur).

**Ban türleri:**

| Ban | Davranış |
|---|---|
| Fixed time | Her engelleme verilen saat kadar sürer (son eşleşmeden itibaren; eşleşme sürdükçe yenilenir) |
| Escalating | İlk engelleme verilen saat, aynı adres aynı koşulla her tekrar engellendiğinde bir öncekinin 2 / 3 / 4 / 5 / 10 katı, *longest block*'a kadar (ör. 24 sa → 48 sa → 96 sa ... 720 sa). Son engellemesi bittikten sonra *start again after* gün (varsayılan 30) temiz kalan adres yeniden ilk adımdan başlar |
| Until the condition is removed | Koşul silinene kadar |

**Block after matches:** 1 = ilk eşleşmede engelle. Daha büyük bir sayı, adresin *within* dakika içinde o kadar ayrı
poll'da eşleşmesini bekler (tek örnek yetmez; yanlış pozitifi azaltır). Eşleşme poll başına bir kez sayıldığından
pencere en az N poll sürmelidir (30 sn poll ile 3 eşleşme için en az 1,5 dk); daha kısası kabul edilmez. Bekleyenler koşul tablosunda "+N waiting" olarak
görünür.

**Suricata severity neden kullanılmıyor:** severity imzanın sınıfının önceliğidir (classtype priority), eşleşmenin ne
kadar kesin olduğu değil. Ör. `policy-violation` sınıfı (bir curl user-agent'ı gibi zararsız trafik) `trojan-activity`
ile aynı şekilde severity 1'dir. "Drop" ise sizin IPS politikanızın bilinçli kararıdır; bu yüzden otomatik filtre ve
önerilen koşul drop'u kullanır.

- LAN hostları, firewall'un kendi adresleri ve *Trusted networks* hiçbir koşulda tabloya eklenmez. Bir LAN ağı
  arayüz yeniden yapılandırılırken bir an görünmese de, collector çalıştığı sürece gördüğü LAN ağları ve daha önce LAN
  hostu olarak kaydedilen adresler de korunur.
- Kural limiti koşulu limitin sayısal değerini değil "kural + limit türü" bilgisini tutar. Limit her poll'da kuraldan
  okunur; max-src-states'i değiştirirseniz koşul yeni değere göre çalışır. Kural numarası değil, kuralın sabit etiketi
  kullanılır, kurallar yeniden sıralansa da koşul doğru kurala bağlı kalır. Etiketi olmayan kurallar için düğme çıkmaz.
  Global source tracking'de (OPNsense varsayılanı) bir kaynak yalnızca o kuralın açtığı bir state'i varsa o kuralın
  limitinde sayılır; başka kurallardaki bağlantıları yüzünden engellenmez.
- Saldırı koşulu hedefin bütün ziyaretçilerini değil, saldırının kendisini gönderen kaynakları alır: reflection'da
  yansıtma portlarından UDP gönderenler, brute force'ta giriş portuna tekrar tekrar bağlananlar, flood'da saldırılan
  porta trafiğin en az %1'ini gönderenler. Örnekte tek bağlantısı görünen kaynak (normal bir ziyaretçi ya da kendi SSH
  oturumunuz) alınmaz. Yine de yönetim adreslerinizi *Trusted networks*'e eklemeniz önerilir.
- Koşula uymaya devam eden adresin süresi her poll'da yeniden başlar. Süre dolan adresler ve silinen koşulun tuttuğu
  adresler tablodan çıkarılır (başka bir koşul tutmuyorsa). `pfctl` başarısız olursa kayıt silinmez, tekrar denenir.
- Koşul eşleştiğinde zaten tabloda olan adres (pf `overload` ya da başka bir araç) "already there" olarak işaretlenir;
  koşul onu tablodan çıkarmaz. O girdi sonradan tablodan giderse adres koşulun olur ve tabloya koşul tarafından eklenir.
- Tablo değişikliği, poll'un veritabanı kaydı tamamlandıktan sonra yapılır; yarıda kalan bir poll tabloda sahipsiz
  adres bırakmaz.
- Yeniden başlatma ya da tablo boşaltılması durumuna karşı koşulların tuttuğu adresler 10 dakikada bir tabloya yeniden
  eklenir. Koşulların tuttuğu adres sayısı toplamda 50.000 ile sınırlıdır.
- Aynı koşul tekrar oluşturulursa yeni koşul açılmaz, mevcut koşulun ban'ı değişir; tuttuğu adresler de yeni süreye
  göre (son eşleşmeden itibaren) çıkar.
- *Addresses blocked by conditions* tablosu her adresin bu engellemesinin ne kadar sürdüğünü ve artan banda kaçıncı
  engellemesi olduğunu gösterir.
- Yetkiler üçe ayrılır:
  - *Reporting: HostGuard*: dashboard, uyarıları onaylama, port testi. Koşulları görür ama ekleyemez.
  - *Services: HostGuard: Settings*: ayarlar, servis, veritabanını temizleme (ağlar ve trusted networks neyin
    korunacağını belirler).
  - **Firewall: HostGuard: Block conditions**: koşul ekleme / silme (pf tablosunu değiştirir).
- OPNsense virusprot girdilerini kendi takvimiyle de silebilir; silinen girdiler en geç 10 dakika içinde geri eklenir.

### Otomatik filtreleme (seviyeli)

*Settings → Automatic filtering* ile dış kaynaklar elle koşul oluşturmadan `virusprot`'a alınır. Tespitler ne kadar
emin olunduğuna göre üç seviyeye ayrılır; seçilen seviye kendisini ve daha emin seviyeleri kapsar. Varsayılan:
kapalı.

| Seviye | Ne alınır | Neden bu seviyede |
|---|---|---|
| **1: certain** (yanlış pozitif pratikte yok) | Tek örnekte (birkaç saniye) TCP SYN'leriyle ya da istemci portundan (1024+) UDP ile bir hostun **20+ farklı portuna** ya da **10+ farklı LAN hostuna** engellenen deneme yapan kaynak; Spamhaus **ASN-DROP** ağlarından gelen engellenen trafik | Normal bir istemci kapalı portları taramaz; ASN-DROP ağları suç için işletilir. Kanıt örneklenmiş gerçek paketlerdir, tahmin değil. TCP'de yalnız SYN'ler sayılır; UDP'de sunucu portundan gelen cevaplar (yansıyan DNS/NTP cevapları), UDP traceroute / mtr / tracepath (hedef port 33000 ve üstü) ve ICMP (hostlar üzerinde gezen izleme ping'leri) tarama sayılmaz. Tek istisna kasıtlı kötüye kullanım: SYN ve UDP paketlerinin kaynak adresi sahte olabilir, biri başka bir adres adına tarama yaparak o adresi engelletebilir (bkz. aşağıda *Trusted networks*) |
| **2: likely** | Dağıtık brute force'ta giriş portuna tekrar tekrar bağlanan kaynaklar (tek bağlantı yapan ziyaretçi alınmaz; posta ve web giriş portları hariç: 25, 110, 143, 465, 587, 993, 995, 8006, 8443); Suricata'nın **drop ettiği** alarmlar (IPS modu; IDS modunda eşleşmez) | Saldırı sırasında kendi SSH oturumunuz ya da hatalı bir imza aralarında olabilir. Posta ve web istemcileri aynı anda birkaç bağlantı açtığı için yoğun bir posta/web sunucusu brute force gibi görünür; onları sunucunun kendi logları (ör. hosttaki CrowdSec) daha iyi ayırır |
| **3: possible** | Flood'larda tekrar eden ve pf'in engellediği trafiği de olan kaynaklar (trafiğin ≥%1'i; yalnız geçen trafik yoğun bir web günü olabilir); kural başına kaynak limitini aşanlar | Paylaşılan adresler (CGNAT, şirket NAT'ı), sahte kaynaklı flood'lar ve geniş imzalar hata olasılığını artırır |

- **Hiçbir seviyede alınmaz:** LAN hostları, firewall'un adresleri, *Trusted networks* (her koşulda olduğu gibi);
  arama motoru / yapay zekâ botları, izleme servisleri, iCloud Private Relay ve CDN adresleri (ağ türü verisi açık
  olmalı); **reflection kaynakları** (istismar edilen DNS / NTP sunucularının kendileri; engellemek onları kullanan
  hostları da etkiler; istenirse elle koşul açılabilir).
- Kendi izleme ve yönetim adreslerinizi, ayrıca engellenmesi pahalıya patlayacak dış adresleri (müşteri ofisleri,
  ödeme / webhook gönderenleri, listelerde olmayan izleme servisleri) *Trusted networks*'e ekleyin: sahte kaynaklı
  paketlerle hiçbir seviyede engelletilemezler.
- Reflection kaynakları hiçbir otomatik kuralla alınmaz: yansıma payı %50'nin altında kalıp saldırı "udp flood"
  sayılsa da, Suricata bir amplification imzası verse de (bir ya da birçok hosta toplamda tekrar eden yansıma cevabı
  gönderen kaynak).
- Kurallar Block conditions sekmesinde "Automatic, level N ..." olarak görünür; orada silinemez, seviye ayardan
  değiştirilir. Seviye düşürülünce ya da kapatılınca yalnız kaldırılan kuralların tuttuğu adresler tablodan çıkar.
- Bir adres son eşleşmesinden *block for* saat (varsayılan 24) sonra çıkar; eşleşmeye devam ederse süre yenilenir.
  Süre değiştirilince zaten engellenmiş adresler de yeni süreye göre (son eşleşmeden itibaren) çıkar.
- *Ban type* = *Escalating* seçilirse aynı kuralla tekrar engellenen adres her seferinde iki katı süre kalır
  (24 → 48 → 96 sa ...), *longest block* saate (varsayılan 720 = 30 gün) kadar; son engellemesi bittikten 30 gün
  sonra baştan başlar.
- Adresleri süresi dolunca tablodan collector çıkarır. HostGuard'ı tamamen kapatırsanız (*Enable* kaldırılır) koşulların
  o an tuttuğu adresler `virusprot`'ta kalır (yeniden açılınca süresi dolanlar çıkarılır). Kapatmadan önce
  *Automatic filtering*'i *off* yapıp koşulları silin ve bir poll bekleyin, ya da sonra **Firewall → Diagnostics →
  Aliases**'tan `virusprot`'u temizleyin.
- Attacks sekmesindeki "Blocked by conditions" kutusu seviyeyi ve bu poll'da esirgenenleri (ör. Googlebot) gösterir.

### Performans

- Saldırı sınıflandırması ek paket yakalamaz, mevcut örnekleri kullanır.
- Suricata log'u baştan okunmaz; her poll'da sadece yeni satırlar, üst sınırla okunur ve sadece `alert` satırları
  JSON olarak çözülür.
- CrowdSec 5 dakikada bir sorgulanır. Kural limitleri zaten her poll'da okunan `pfctl -vvsr` çıktısından gelir.
- Engelleme poll başına en fazla 2000 adresle sınırlıdır ve `pfctl` çağrıları 500'lük gruplar halinde yapılır.

### Traffic shaper

`ipfw pipe show` / `ipfw queue show` okunur. Pipe ve queue açıklamaları, maskeler ve hangi shaper kuralının nereye
gittiği **Firewall → Shaper** ayarlarından alınır.

- **Pipe:** bant genişliği limiti. Maske varsa (src-ip / dst-ip) her IP bu limitin tamamını alır; maske yoksa limit
  herkes arasında paylaşılır.
- **Queue:** bağlı olduğu pipe'ı ağırlığına göre paylaşır.
- **Ölçülenler:** IP başına anlık hız (bayt sayacı farkından), limite göre doluluk, saniyede düşürülen paket. Düşen paket,
  limitin dolduğunu gösterir.
- **Uyarı:** "Shaper limit reached" (varsayılan ≥ 5 pkt/s düşüş). Engellenen trafikte sebep olarak da
  `shaper pipe N "açıklama" rate limit drops` yazılır.

### Transparent bridge modu

- Bridge arayüzlerinin genelde IP'si yoktur, bu yüzden müşteri subnet'lerini **Additional networks**'e mutlaka ekleyin.
- Firewall'un ARP tablosu bridge'de neredeyse boştur. MAC/IP takibi bu yüzden seçilen arayüzlerde ARP ve IPv6 NDP
  paketlerini **pasif dinleyerek** (`tcpdump -e`, yalnızca ARP/ND filtresiyle) yapılır. Bridge cihazı seçildiyse
  üyeleri dinlenir. Ayar: *MAC / IP source*.
- Upstream gateway her müşteri subnet'i için bir IP kullanıyorsa "Multiple IPs on one MAC" uyarısı verir. Gateway'in MAC'ini
  *Ignore MAC addresses*'e ekleyin.
- **pflog:** Engellenen paketler pflog'a yalnızca kural *Log* işaretliyse düşer. Log kapalıysa eklenti engellenen trafiği
  yukarıdaki örnekleme ve kural sayaçlarıyla görür. Firewall log'unu okuma seçeneği hâlâ var ama varsayılan olarak kapalıdır.
  Limitlere takılan paketler (state tablosu dolu, max-src-conn vb.) zaten hiçbir zaman log üretmez; bunlar pf sayaçlarından izlenir.
- **Settings** sayfasının altındaki **Collector status** paneli collector'ın ne gördüğünü gösterir: bulunan ağlar, bridge ve üyeleri,
  dinlenen arayüzler ve paket sayıları, firewall log'u okunabiliyor mu, state tablosu. Kurulumu doğrulamak için buraya bakın.

### Uyarı kuralları

| Tür | Önem | Ne zaman |
|---|---|---|
| LAN → LAN connection | high (SSH, RDP, SMB, veritabanları vb.), diğerleri medium | Kaynak → hedef:port ikilisi o gün ilk kez görüldüğünde (günde bir kez, tekrarlar sayılır) |
| LAN → LAN scan | critical | 5 dk içinde eşik aşılırsa (saatte bir uyarı; o kaynağın tek tek bağlantı uyarıları bunun altında toplanır) |
| Multiple IPs on one MAC | medium | Aynı MAC aynı anda 2+ IPv4 ile görülürse |
| IP changed | medium | MAC, değişim penceresi (varsayılan 24 saat) içinde başka bir IPv4'e geçerse |
| IP moved to another MAC | high → critical | IP başka bir MAC'te görülürse; 3. geçişte critical |

IPv6 adresleri MAC/IP tablosunda gösterilir ama "çoklu IP" uyarısı üretmez (SLAAC/privacy adresleri normalde çoktur).
VRRP/CARP sanal MAC'leri yok sayılır. Meşru olarak çok IP kullanan cihazları (*Ignore MAC addresses*) ve
birbirine bağlanması normal olan sunucuları (*Trusted networks*, ör. yedekleme/izleme) ayarlardan muaf tutabilirsiniz. Aynı alan block koşullarından ve
otomatik filtrelemeden de korur; dışarıdaki izleme ve yönetim adresleriniz de buraya girer.

Suricata ve CrowdSec ile çakışmaz: onların kararlarını ve uyarılarını yalnızca okur. Bağlantı istatistikleri pf'nin state
tablosundan gelir; paket yakalama yalnızca sınırlı örneklemeyle (engellenen trafik, `tcpdump -Q in`) ve pasif ARP/ND
dinlemeyle yapılır. Bağlantı istatistiklerinde varsayılan olarak cevapsız bağlantılar (port taramaları, RST ile
reddedilenler) sayılmaz (ayar: *Answered connections only*).

## Kurulum (elle)

```sh
# bilgisayarınızdan:
scp os-hostguard.tar.gz root@FIREWALL:/tmp/
# firewall'da (konsol 8 / SSH):
cd /tmp && tar xzf os-hostguard.tar.gz && sh os-hostguard/install.sh
```

Sonra web arayüzünü yenileyin:

1. **Reporting → HostGuard → Settings**
2. *Enable* işaretleyin, *LAN interfaces* seçin.
   VDS'ler yönlendirilmiş/bridge public bloklardaysa bunları *Additional networks*'e ekleyin (ör. `203.0.113.0/24`).
3. **Apply**. Birkaç poll sonrası **Reporting → HostGuard → Dashboard** dolmaya başlar.

**os-lanusage'dan geçiş:** `install.sh` (ve paket kurulumu, `+POST_INSTALL.post`) eski `lanusage` servisini
durdurur, `/var/db/lanusage/lanusage.db` veritabanını (geçmiş, uyarılar)
`/var/db/hostguard/hostguard.db` olarak taşır ve eski dosyaları kaldırır. os-lanusage paket olarak kuruluysa
`install.sh` onu `pkg delete` ile kaldırır; HostGuard paket olarak kurulduğunda ise eski paketin dosyalarına
dokunulmaz, **System → Firmware → Plugins**'ten (ya da `configctl firmware remove os-lanusage`) kaldırmanız
istenir; sadece `pkg delete` eklenti listesinde bırakır, bir eşitleme onu geri kurar. config.xml'deki ayarları (`OPNsense/lanusage`) model
geçişi (`Migrations/M1_7_0.php`) HostGuard bölümü henüz yokken bir kez `OPNsense/hostguard` altına alır; yeni modelin
kabul etmediği bir değer (ör. silinmiş bir arayüz) varsayılanında kalır. Eski bölüm silinmez, yalnızca kapatılır
(`enabled=0`): os-lanusage yeniden kurulursa kapalı başlar. Ayarlar alınamazsa `install.sh` (ya da paket kurulumu)
bunu yazar; o durumda **Reporting → HostGuard → Settings**'ten girin. Kullanıcı yetkileri yeni adlarıyla
(*Reporting: HostGuard* ...) yeniden atanmalıdır.

Kaldırma: `sh os-hostguard/uninstall.sh` (veritabanını da silmek için `--purge`).

### Paket olarak derlemek
Klasörü bir [opnsense/plugins](https://github.com/opnsense/plugins) checkout'unda `net-mgmt/hostguard/`
altına koyup `make package` ile `os-hostguard` paketi üretilebilir (Makefile hazır).

## Ayarlar

| Ayar | Varsayılan | Not |
|---|---|---|
| Poll interval | 30 sn | Bundan kısa süren bağlantılar kaçabilir. Yük düşükse 10–15 sn yapılabilir. |
| Retention | 30 gün | Eski kayıtlar saatlik temizlenir. |
| Answered connections only | açık | Taramaları ve cevapsız denemeleri dışarıda bırakır. |
| Ignore firewall traffic | açık | Firewall'un kendi IP'leri ve kendi başlattığı bağlantılar (servis testleri dahil) sayılmaz. |
| Record remote addresses | açık | Çok yoğun web sunucularında kapatılırsa DB küçülür (remote yerine `*`). |
| Automatic service test | açık | Dakikada en fazla *Tests per minute* port, her port *Re-test after* saatte bir yeniden test edilir. |
| Never test ports | boş | Bağlanılmasını istemediğiniz portlar (ör. `25,8000-8100`). |
| Use nmap | kapalı | `pkg install nmap` sonrası açılabilir; daha yavaş ama daha çok servis tanır. |
| Owner and network type of sources | açık | Günde bir kez (bir liste inmezse üç saat sonra bir kez daha) ücretsiz listeleri indirir (~15 MB indirme, ~35 MB disk); kapatılırsa indirme yapılmaz. |
| Also hosting | boş | Hosting sayılacak AS'ler, ör. `AS16276,AS24940` (AS kategorisinden önce, adres listelerinden sonra). |
| Automatic filtering | kapalı | Seviye 1 / 1+2 / 1+2+3 (yukarıdaki tablo). |
| Automatic filtering: block for | 24 saat | Son eşleşmeden sonra tabloda kalma süresi (artan banda ilk engelleme). |
| Automatic filtering: ban type | Fixed | *Escalating*: aynı kuralla her tekrar engellemede süre iki katı. |
| Automatic filtering: longest block | 720 saat | Artan banın ulaşabileceği en uzun süre. |

Servis testleri yalnızca izlenen LAN ağlarındaki adreslere yapılır; dış IP'ler hiçbir zaman taranmaz.

## Mimari

```
pf state table ──(pfctl -ss -v, her 30 sn)──> collector.py (daemon) ──> /var/db/hostguard/hostguard.db (SQLite, WAL)
                                                   └─ prober thread ──> detect.py ──> services tablosu
Web GUI (Volt + JS SVG grafikler) ──> /api/hostguard/stats/*, /api/hostguard/conditions/* (PHP) ──> configd "hostguard query/probe" ──> query.py / probe.py
```

| Dosya | Görev |
|---|---|
| `src/opnsense/scripts/OPNsense/HostGuard/collector.py` | Daemon: state okuma, tekilleştirme (NAT'lı iki state = 1 bağlantı), sayma, yazma, temizlik, otomatik test |
| `.../lib/pfstate.py` | `pfctl -ss -v` çıktısı ayrıştırıcı (IPv4/IPv6, NAT, yön) |
| `.../lib/detect.py` | Servis tespiti |
| `.../lib/l2.py`, `.../lib/filterlog.py` | ARP/NDP tablosu ve pasif ARP/ND dinleme (bridge), firewall log'undan engellenen paketleri artımlı okuma |
| `.../lib/sampler.py` | Sınırlı süre/paketle bağlantı denemesi örnekleme (engellenen trafik için) |
| `.../lib/attacks.py` | Gelen saldırı türü sınıflandırması, Suricata eve.json okuyucu, CrowdSec kararları |
| `.../lib/shaper.py` | `ipfw pipe/queue show` ve Firewall → Shaper ayarlarını okuma |
| `.../lib/pfstats.py` | `pfctl -vsi / -sm / -vvsr / -sT` okuma: sayaçlar, limitler, kural limitleri, tablolar |
| `.../lib/ipdata.py`, `.../update_ipdata.py` | Ağ türü / sahip listelerini indirme (günde bir, collector'ın alt süreci) ve yerel sorgu |
| `.../lib/autofilter.py` | Otomatik filtreleme seviyeleri, kuralları ve esirgenen trafik |
| `.../lib/bans.py` | Koşulların ban türleri: sabit, artan süre, eşleşme eşiği |
| `.../query.py`, `.../probe.py` | configd tarafından çağrılan JSON okuma / elle test |
| `src/opnsense/mvc/...` | Model, ayar formu, menü, ACL, API ve görünümler |
| `src/opnsense/www/js/hostguard.charts.js` | Bağımlılıksız SVG grafik kütüphanesi |
| `src/etc/rc.d/hostguard`, `src/etc/inc/plugins.inc.d/hostguard.inc` | Servis (daemon(8) ile, çökerse yeniden başlar) ve Services widget kaydı |

Loglar: **System → Log Files → General** (`hostguard`). Komut satırından:
`configctl hostguard status`, `configctl hostguard query summary 24 - -`.

## Bilinen sınırlar

- **LAN ↔ LAN görünürlüğü:** Yalnızca firewall'dan geçen trafik görünür: farklı arayüz/subnet arası trafik
  ya da filtreleyen bridge. Aynı switch'te aynı subnet'teki iki VDS arasındaki trafik firewall'a hiç
  uğramaz, bunun için switch port mirroring + IDS gerekir.
- **Engellenen denemeler:** Log gerektirmez, örneklemeyle tahmin edilir (yukarıya bakın).
- **MAC/IP takibi:** Firewall'un ARP tablosuna dayanır, yani firewall'un gateway olduğu (routed)
  kurulumlarda tam çalışır. Saf bridge modunda yalnızca firewall'un kendisiyle konuşan hostlar görünür.

- Poll tabanlıdır: iki okuma arasında başlayıp biten çok kısa bağlantılar (ör. tek DNS sorgusu) kaçabilir.
  Daha hassas sayım gerekirse ileride NetFlow (Reporting → NetFlow) kaynağı eklenebilir.
- "Connections" tablosundaki sayılar gün bazında toplanır; 1–6 saatlik aralıkta o günün tamamı görünebilir.
  Grafikler ve port istatistikleri 5 dk / 1 saatlik çözünürlüktedir.
- Arayüz metinleri OPNsense geleneğine uygun olarak İngilizce ve `lang._()` ile sarılıdır.
