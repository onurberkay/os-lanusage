# os-lanusage — OPNsense LAN Usage eklentisi

LAN'daki (müşteri VDS'leri) her IP'nin hangi portu / servisi kullandığını kaydeder,
**Reporting → LAN Usage** menüsünde grafik ve tablolarla gösterir ve kullanılan portlara
servis testi yaparak arkasında ne çalıştığını tespit eder.

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
| Alerts | Tüm uyarılar önem derecesiyle tek listede, onaylanabilir (acknowledge). Overview'da açık uyarı şeridi, menüde **Reporting → LAN Usage → Alerts** kısayolu. Yeni uyarılar syslog'a da `ALERT [...]` satırı olarak yazılır. |

| States / Limits | pf state tablosu doluluğu, limit sayaçları (`memory`, `state-limit`, `src-limit`, `max-src-conn(-rate)`, `overload table insertion`, `synfloods detected`, NAT `map-failed` …), "max states" sınırına yaklaşan kurallar, LAN host başına state sayısı ve saniyedeki yeni bağlantı. virusprot / sshlockout / CrowdSec tablolarına düşen LAN hostları. Menüde **Reporting → LAN Usage → States / Limits**. |

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
2. **Block kuralı sayaçları (kesin):** Her poll'da `pfctl -vvsr` ile block kurallarının paket sayaçları okunur. Kural başına
   anlık paket/sn ve dönem toplamı gösterilir. Açıklamalar `/tmp/rules.debug`'dan alınır. Host bilgisi vermez ama kesin değerdir.

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
| Too many states (host) | high, 2 katında critical | Bir LAN host'u ≥ *States per LAN host* (varsayılan 10 000) state tuttuğunda. Ağırlıklı inbound ise "DDoS hedefi olabilir", outbound ise "flood / ele geçirilmiş olabilir" diye yazar. |
| Connection rate (host) | high | Bir LAN host'u saniyede ≥ 300 yeni bağlantı açtığında / aldığında |
| LAN host in block table | virusprot/sshlockout: high, CrowdSec: critical | Bir LAN IP'si izlenen bir pf tablosuna eklendiğinde |
| Source at rule limit | LAN kaynağı: high, dış kaynak: medium | Bir kaynak IP, kuralındaki `max-src-states`, `max-src-conn` ya da `max-src-conn-rate` sınırına ulaştığında. `pfctl -sS -v` (source tracking) okunur; uyarıda IP, limit (değer/sınır) ve kural (numara + açıklama) yazar. `src-limit` / `max-src-*` sayaç uyarıları da artık tahmin yerine o an limitte olan kaynakları yazar. %90'ı geçen kaynaklar States / Limits sekmesinde listelenir. |

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
birbirine bağlanması normal olan sunucuları (*Trusted LAN hosts*, ör. yedekleme/izleme) ayarlardan muaf tutabilirsiniz.

Suricata ve CrowdSec ile çakışmaz: eklenti paket yakalamaz, yalnızca pf'nin state tablosunu okur.
Engellenen trafik state oluşturmadığı için kayıtlara girmez; varsayılan olarak cevapsız
bağlantılar (port taramaları, RST ile reddedilenler) da sayılmaz.

## Kurulum (elle)

```sh
# bilgisayarınızdan:
scp os-lanusage.tar.gz root@FIREWALL:/tmp/
# firewall'da (konsol 8 / SSH):
cd /tmp && tar xzf os-lanusage.tar.gz && sh os-lanusage/install.sh
```

Sonra web arayüzünü yenileyin:

1. **Reporting → LAN Usage → Settings**
2. *Enable* işaretleyin, *LAN interfaces* seçin.
   VDS'ler yönlendirilmiş/bridge public bloklardaysa bunları *Additional networks*'e ekleyin (ör. `203.0.113.0/24`).
3. **Apply**. Birkaç poll sonrası **Reporting → LAN Usage → Dashboard** dolmaya başlar.

Kaldırma: `sh os-lanusage/uninstall.sh` (veritabanını da silmek için `--purge`).

### Paket olarak derlemek
Klasörü bir [opnsense/plugins](https://github.com/opnsense/plugins) checkout'unda `net-mgmt/lanusage/`
altına koyup `make package` ile `os-lanusage` paketi üretilebilir (Makefile hazır).

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

Servis testleri yalnızca izlenen LAN ağlarındaki adreslere yapılır; dış IP'ler hiçbir zaman taranmaz.

## Mimari

```
pf state table ──(pfctl -ss -v, her 30 sn)──> collector.py (daemon) ──> /var/db/lanusage/lanusage.db (SQLite, WAL)
                                                   └─ prober thread ──> detect.py ──> services tablosu
Web GUI (Volt + JS SVG grafikler) ──> /api/lanusage/stats/* (PHP) ──> configd "lanusage query/probe" ──> query.py / probe.py
```

| Dosya | Görev |
|---|---|
| `src/opnsense/scripts/OPNsense/LanUsage/collector.py` | Daemon: state okuma, tekilleştirme (NAT'lı iki state = 1 bağlantı), sayma, yazma, temizlik, otomatik test |
| `.../lib/pfstate.py` | `pfctl -ss -v` çıktısı ayrıştırıcı (IPv4/IPv6, NAT, yön) |
| `.../lib/detect.py` | Servis tespiti |
| `.../lib/l2.py`, `.../lib/filterlog.py` | ARP/NDP tablosu ve pasif ARP/ND dinleme (bridge), firewall log'undan engellenen paketleri artımlı okuma |
| `.../lib/sampler.py` | Sınırlı süre/paketle bağlantı denemesi örnekleme (engellenen trafik için) |
| `.../lib/pfstats.py` | `pfctl -vsi / -sm / -vvsr / -sT` okuma: sayaçlar, limitler, kural limitleri, tablolar |
| `.../query.py`, `.../probe.py` | configd tarafından çağrılan JSON okuma / elle test |
| `src/opnsense/mvc/...` | Model, ayar formu, menü, ACL, API ve görünümler |
| `src/opnsense/www/js/lanusage.charts.js` | Bağımlılıksız SVG grafik kütüphanesi |
| `src/etc/rc.d/lanusage`, `src/etc/inc/plugins.inc.d/lanusage.inc` | Servis (daemon(8) ile, çökerse yeniden başlar) ve Services widget kaydı |

Loglar: **System → Log Files → General** (`lanusage`). Komut satırından:
`configctl lanusage status`, `configctl lanusage query summary 24 - -`.

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
