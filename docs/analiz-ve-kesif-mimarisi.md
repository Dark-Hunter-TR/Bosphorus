# Bosphorus — Proje Analizi, DPI Araçları Karşılaştırması ve Keşif Mimarisi

> Bu belge kod tabanının **mevcut durumunu** (commit `20ee707`) inceleyip üç soruyu
> yanıtlar:
> 1. Bosphorus'un diğer DPI atlatma araçlarından gerçek farkı nedir?
> 2. ~166 adaylık gridin **paralel denenmesi** nasıl tasarlanmıştır?
> 3. Bir adayın başarısı **nasıl tekrar doğrulanır** (terfi/düşürme mimarisi)?
>
> Bulgular kod okunarak çıkarılmış, kritik olanlar ise geçici testlerle
> çalıştırılarak doğrulanmıştır. Doğrulama yöntemi ilgili bölümde belirtilir.

---

## İçindekiler

- [1. Yönetici özeti](#1-yönetici-özeti)
- [2. Sistem haritası](#2-sistem-haritası)
- [3. Diğer DPI araçlarıyla fark](#3-diğer-dpi-araçlarıyla-fark)
- [4. ~166 adayın paralel denenmesi — tasarım mimarisi](#4-166-adayın-paralel-denenmesi--tasarım-mimarisi)
- [5. Başarıyı tekrar doğrulama mimarisi](#5-başarıyı-tekrar-doğrulama-mimarisi)
- [6. Doğrulanmış bulgular](#6-doğrulanmış-bulgular)
- [7. Kapsam boşlukları ve riskler](#7-kapsam-boşlukları-ve-riskler)
- [8. Öncelikli yol haritası](#8-öncelikli-yol-haritası)

---

## 1. Yönetici özeti

Bosphorus, WinDivert üzerinden `:443` (+ Cloudflare alternatif HTTPS portları)
TLS el sıkışmalarını yakalayan, **hedef başına** hangi paket manipülasyon
stratejisinin DPI'ı yendiğini **kendi kendine öğrenen** ve sonucu **bağlı olunan
ağa göre anahtarlanmış** biçimde diske kaydeden bir Rust workspace'idir.

Mimarinin ayırt edici omurgası üç parçadır:

| Katman | Ne yapar | Nerede |
|---|---|---|
| **Kapalı döngü geri besleme** | Gerçek trafiğin sonucunu (`ServerHello` / `RST` / karadelik) stratejiye geri bağlar | `conntrack/events.rs`, `engine.rs:410` |
| **Fırsatçı paralel tarama** | Aynı hedefe eşzamanlı açılan bağlantılara **farklı** adaylar dağıtır | `profile/mod.rs:184`, `discovery/scheduler.rs:104` |
| **Ağ anahtarlı kalıcılık** | Öğrenileni NetKey başına JSON'a yazar, grid büyüyünce yeniden canlandırır | `profile/persist.rs`, `discovery/mod.rs:94` |

**Genel değerlendirme.** Tasarım olgun: durum makinesi net, bellek sınırlaması
(tahliye + 4096 tavan + `compact()`) düşünülmüş, güvenlik kararları (overlap
opt-in, SNI'siz ClientHello'ya dokunmama, `panic = "unwind"`) gerekçelendirilmiş
ve 147 birim testi Linux'ta bile geçiyor (`cargo test -p bosphorus-core`).

**Ancak** doğrulama mantığında somut bir kusur var: terfi eşiği olan "arka arkaya
2 başarı" sayacı **hedef bazlı**, aday bazlı değil. Paralel tarama tam olarak bu
sayacın karışmasına yol açan koşulu üretir; sonuç, **kendisi yalnızca 1 kez
başarılı olmuş bir adayın terfi edebilmesidir**. Bu davranış testle üretilmiştir
([Bulgu 1](#bulgu-1-terfi-sayacı-hedef-bazlı-aday-bazlı-değil)). İkinci önemli
konu, **tek bir başarısızlığın bir adayı o hedef için kalıcı olarak elemesi** ve
bu elemenin diske yazılmasıdır ([Bulgu 2](#bulgu-2-tek-başarısızlık-kalıcı-eleme-üretir)).

---

## 2. Sistem haritası

### 2.1 Crate'ler

| Crate | Sorumluluk | Platform |
|---|---|---|
| `bosphorus-core` | Paket ayrıştırma, conntrack, strateji modeli + grid üreteci, keşif zamanlayıcısı, kalıcılık | Platformdan bağımsız (WinDivert bağımlılığı yok) |
| `bosphorus-divert` | WinDivert 2.2 üzerine ince, tahsissiz güvenli sarmalayıcı | `#![cfg(windows)]` |
| `bosphorus-cli` | Binary, Windows Servisi, NetKey hesabı, rota izleyici, loglama, EN/TR katalog, TUI launcher | Windows |

Çekirdeğin ağa `PacketSource` / `PacketSink` trait'leri üzerinden bakması,
motorun tamamının sürücüsüz test edilebilmesini sağlar — nitekim çekirdek test
paketi Linux'ta çalışır.

### 2.2 Bir paketin yolu

```
WinDivert recv
   │
   ▼
Engine::process (engine.rs:225)
   ├─ impostor / IP olmayan / TCP olmayan  ──────────────► ForwardOriginal
   ├─ conntrack::observe_{outbound,inbound}   ─► verdict? ─► feed_discovery
   └─ outbound && TLS portu && ClientHello?
          │
          ▼
      act_on_client_hello (engine.rs:290)
          ├─ strategy_applied (retransmit)  ─────────────► ForwardOriginal
          ├─ SNI okunamıyor (ECH/parçalı)   ─────────────► ForwardOriginal
          ├─ Discovery::assign(target, server_ttl)
          └─ apply_strategy ─► SendBatch ─► ForwardBatch{Only,ThenOriginal}
```

Bakım işleri ayrı bir tick thread'inde 2 Hz döner
(`engine_cmd.rs:501`, `sleep(500ms)`): akış süpürme, zaman aşımı kararları,
ilerleme özeti (10 sn), tahliye (60 sn), kalıcılaştırma (30 sn), bellek özeti
(60 sn), ağ değişimi yeniden bağlama.

---

## 3. Diğer DPI araçlarıyla fark

### 3.1 Konumlandırma tablosu

| Araç | Çalışma noktası | Strateji seçimi | Geri besleme kaynağı | Hafıza birimi | Ağ değişimi |
|---|---|---|---|---|---|
| **GoodbyeDPI** | WinDivert sürücüsü (Windows) | **Manuel** — bayraklar / hazır presetler (`-1`…`-9`) | Yok (açık döngü) | Yok | Yok |
| **zapret** (`nfqws`/`winws`) | NFQUEUE (Linux) / WinDivert (Windows) | **Manuel**, ama `blockcheck.sh` ile yarı otomatik | **Bant dışı**: script `curl` ile ayrı test bağlantıları açar | Yok (çıktı = elle uygulanacak parametre listesi) | Yok |
| **ByeDPI / ciadpi** | Yerel SOCKS5/HTTP proxy (sürücü yok) | Kullanıcının tanımladığı **birkaç** `--auto` grubu, soldan sağa | **Bant içi**: `torst` / `ssl_err` / `redirect` tetikleyicileri | IP+alan adı önbelleği, TTL'li (varsayılan ~28 saat, `--cache-ttl`) | Yok |
| **SpoofDPI / GreenTunnel** | Yerel proxy | Sabit tek teknik (ilk paket bölme) | Yok | Yok | Yok |
| **PowerTunnel** | Yerel proxy / VPN (Java) | Modül + preset | Sınırlı | Sınırlı | Yok |
| **Bosphorus** | WinDivert sürücüsü (Windows) | **Tam otomatik**: 166 adaylık sıralı grid taraması | **Bant içi**: kullanıcının kendi trafiğinin `ServerHello`/`RST`/karadelik kararı | **SNI hedefi × NetKey**, süresiz JSON | **Var** — rota/adres değişiminde oturum yeniden anahtarlanır |

### 3.2 En yakın iki rakiple net ayrım

**zapret `blockcheck.sh` ile fark — "bant dışı toplu tarama" vs "bant içi sürekli öğrenme".**
`blockcheck`, kurulum öncesi bir kez çalıştırılan bir teşhis aracıdır: kendi
`curl` bağlantılarını açar, stratejileri sırayla dener, çalışanları listeler ve
**siz** çıkan parametreyi elle yapılandırmaya yazarsınız. Bu; (a) tek seferliktir,
(b) test ettiği alan adları listeye bağlıdır, (c) sonucu tüm trafiğe uygulanan
tek bir global stratejidir, (d) ağ değişince tekrar çalıştırmanız gerekir.
Bosphorus'ta aynı işlev **motorun içinde, sürekli ve hedef bazlıdır**: ayrı bir
tarayıcı süreç yok, sentetik bağlantı yok — tarama, uygulamanın zaten açtığı
bağlantıların üstünde yürür ve öğrenilen strateji o hedefe **anında** uygulanır.
Buna karşılık `blockcheck`'in bir üstünlüğü de vardır: DNS zehirlenmesini de
sınar ve gerektiğinde DoH'a geçer; Bosphorus'ta DNS yalnızca gözlemlenebilir
durumda ([§7](#7-kapsam-boşlukları-ve-riskler)).

**ByeDPI `--auto` ile fark — "birkaç el yapımı grup" vs "üretilmiş grid".**
ByeDPI gerçekten bant içi geri besleme (`torst`, `ssl_err`) ve IP+alan adı
önbelleği kullanır; bu, kavramsal olarak Bosphorus'a en yakın tasarımdır. Ayrımlar:

- **Arama uzayı**: ByeDPI'de gruplar kullanıcı tarafından yazılır ve pratikte
  bir avuçtur. Bosphorus'ta grid **eksenlerin kartezyen çarpımından üretilir**
  (166 aday) ve başarı olasılığına göre sıralanır — kullanıcı hiçbir şey yazmaz.
- **Katman**: ByeDPI bir SOCKS proxy'sidir; istemcinin ona yönlendirilmesi
  gerekir ve manipülasyon uygulama soketi seviyesindedir. Bosphorus sürücü
  seviyesindedir: yönlendirme gerekmez, tüm makine kapsanır ve TTL'li sahte
  paket / yanlış sağlama toplamı gibi **ham IP/TCP teknikleri** mümkündür —
  bunlar bir proxy'nin erişemediği alandır.
- **Hafıza anahtarı**: ByeDPI IP+alan adını TTL ile önbelleğe alır. Bosphorus
  SNI hedefini **ağ kimliğiyle** (ağ geçidi IPv4 + CIDR + DNS son eki hash'i)
  birlikte anahtarlar ve süresiz saklar; ev/ofis/hotspot arasında dolaşırken her
  ağ kendi öğrendiğini korur.
- **Sunucu yığını farkındalığı**: Bosphorus `SYN+ACK` TTL'inden sunucunun
  başlangıç TTL'ini (64/128/255) tahmin edip `OverlapDisorder` ailesini
  Windows (ilk-gelen-kazanır) sunuculardan uzak tutar (`scheduler.rs:14`).

### 3.3 Miras alınan kısımlar (dürüstlük notu)

Bosphorus sıfırdan bir teknik icat etmiyor: WinDivert filtre parçaları ve
517 baytlık sahte `ClientHello` GoodbyeDPI'dan **birebir** alınmış ve kodda
"düzeltmeyin" diye işaretlenmiş (`filter/templates.rs`); `disorder + seqovl` ve
otomatik TTL sezgiseli zapret'ten modellenmiş. **Katkı teknikte değil, tekniklerin
otomatik seçilmesi, doğrulanması ve hatırlanmasındadır.**

---

## 4. ~166 adayın paralel denenmesi — tasarım mimarisi

### 4.1 Grid nasıl oluşur

`build_grid` (`strategy/generator.rs:175`) eksenlerin çarpımını alır ve
`StrategyId` (içerik hash'i) üzerinden tekilleştirir. Varsayılan grid **166**,
`--enable-overlap` ile **174** adaydır (test ile ölçüldü):

| Aile | Adet | İndeks aralığı | Üretim |
|---|---:|---|---|
| Tek bölmeli parça + sahte paket | 142 | 0–141 | 7 çapa × {ileri, ters} × 6 desync × {1,2} tekrar, tekilleştirilmiş |
| Çok parçalı yerel bölme | 12 | 142–153 | 3 kalıp × {ileri, ters} × {sahte yok, wrong-seq} |
| RFC 7685 `tls_pad` (512 B) | 6 | 154–159 | 3 çapa × {wrong-seq, wrong-cksum} |
| "Agresif" sahte paket | 6 | 160–165 | 3 çapa × {wrong-seq, wrong-cksum} |
| `OverlapDisorder` (opt-in) | +8 | 166–173 | 4 çapa × 2 `seqovl` |

Sıralama tesadüfi değil: `frag_anchor` ve `desync` eksenleri **kaba başarı
olasılığına göre** dizilmiştir, dolayısıyla `next_candidate` daima listenin
başındaki ucuz kazanımları önce dağıtır. Ölçülen ilk beş aday:

```
0: fake(wrong-seq)+frag@sni      3: fake(wrong-cksum)+frag@sni
1: fake(wrong-seq)x2+frag@sni    4: fake(wrong-cksum)x2+frag@sni
2: frag@sni
```

`StrategyId`, stratejinin alanları üzerinden FNV-1a ile hesaplanan bir **içerik
hash'idir** (`strategy/model.rs:183`). Bu tercih kalıcılığın temelidir: grid
yeniden sıralandığında indeksler kayar ama id'ler kaymaz; diskten yüklenen id
canlı gridde yoksa o hedefin strateji verisi düşürülüp yalnızca öğrenilmiş TTL
korunur (`discovery/mod.rs:94`).

### 4.2 Paralelliğin gerçek doğası: fırsatçı, üretilmiş değil

**Kritik tasarım kararı:** Bosphorus tarama için **sentetik bağlantı açmaz**.
Paralellik, uygulamanın (tarayıcı, Discord istemcisi…) aynı hedefe zaten
eşzamanlı açtığı TCP bağlantılarından türetilir. Bir deneme biriminin tanımı:
**bir akış = bir ClientHello = bir aday**.

Sonuçları:

- **Avantaj**: sıfır ek trafik, sıfır sentetik gürültü — tarama sansürcüye
  "anormal tarama" gibi görünmez, kullanıcının normal davranışının içinde erir.
- **Maliyet**: tarama hızı **uygulamanın yeniden deneme hızıyla sınırlıdır**.
  Tek bağlantı açan bir uygulama için 166 aday, en kötü durumda 166 ardışık
  denemedir. Kod bunun farkında: ilerleme özeti (`engine.rs:676`) yavaş taramayı
  görünür kılmak için özellikle eklenmiş.

### 4.3 Eşzamanlılık çekirdeği: `in_flight`

Aynı hedefe iki bağlantının **aynı** adayı denemesini önleyen mekanizma:

```rust
// profile/mod.rs:184
pub fn skip_ids(&self) -> Vec<StrategyId> {
    let mut v = self.tried.clone();                       // kalıcı olarak elenmiş
    v.extend(self.in_flight.iter().map(|f| f.id));        // şu an denenmekte
    v
}
```

`assign_seeded` her çağrıda sırasıyla:

1. `expire_in_flight(now, in_flight_ttl)` — 15 sn'den eski, kararı hiç gelmemiş
   denemeleri serbest bırakır (`config.rs:192`). Bu, kaybolan bir akışın bir
   adayı sonsuza dek rehin almasını engeller.
2. `revive_if_grid_grew` — `Exhausted` hedefi, grid büyüdüyse `tried` korunarak
   `Discover`'a döndürür (`scheduler.rs:235`).
3. Faz'a göre aday seçer.
4. `mark_assigned` — **yalnızca `Discover` fazında ve id varsa** `in_flight`'e
   ekler (`profile/mod.rs:199`). `Probe` (passthrough) ve `Active` (tek stratejinin
   tekrarı) izlenmez; doğru tercih.

**Doygunluk davranışı — mimarinin en zarif detayı.** Kalan tüm adaylar başka
bağlantılarda uçuştaysa `next_candidate(&skip_ids)` `None` döner. Naif bir
uygulama burada `Exhausted` derdi. Kod bunun yerine **ikinci bir sorgu** yapar:

```rust
// scheduler.rs, Discover kolu
if gen.next_candidate(&ts.tried, &accept).is_none() {
    ts.phase = NetPhase::Exhausted;   // gerçekten hepsi elendi
} else {
    /* passthrough; Discover'da kal */ // sadece meşguller
}
```

Yani "gerçekten tükendi" ile "şu an hepsi meşgul" ayrımı yapılır; ikincisinde
bağlantı dokunulmadan geçer ve hedef taramada kalır. Test: `scheduler.rs`
→ `saturated_in_flight_passes_through_without_exhausting`.

### 4.4 Arama uzayını daraltan tohumlama (seeding)

Kör tarama 166 denemeye kadar sürebileceği için, `build_seeds`
(`discovery/mod.rs:369`) aynı ağda **zaten çalışan** stratejileri öne alır:

| Katman | Kaynak | Terfi eşiği | Probe atlanır mı |
|---|---|---:|---|
| `DomainSibling` | Aynı kayıtlı alan adındaki `Active` hedefin terfi etmiş stratejisi | **1** | Evet |
| `HouseStrategy` | Oturumdaki en yaygın 3 `active` strateji ("ev stratejisi") | **1** | Evet |
| `IpProximity` | Ayrılmış; henüz hiçbir yerde üretilmiyor | varsayılan (2) | Hayır |

İki incelik:

- Kayıtlı alan adı çıkarımı **Public Suffix List kullanmaz**; son iki (bazen üç)
  etiketi alan kaba bir sezgiseldir ve bilinçli olarak öyledir — yanlış gruplama
  yalnızca **bir deneme** maliyetindedir, hedefler asla birleştirilmez.
- Yüksek güvenli bir tohum varsa **çıplak `Probe` tamamen atlanır**
  (`scheduler.rs`, `NetPhase::Probe` kolu): "engelli mi?" sorusunu bir RST
  pahasına sormak yerine, komşuda kanıtlanmış strateji ilk temasta uygulanır.
- Tohum sıralaması `StrategyQuality` ile yapılır: önce **retransmit'siz** başarı
  gösterenler (`looks_fast()`), sonra en düşük gecikmeli olanlar.

### 4.5 Gating: her aday her sunucuya verilmez

```rust
// scheduler.rs:14
fn accept_for(server_initial_ttl: Option<u8>) -> impl Fn(&Strategy) -> bool {
    move |s| !(server_initial_ttl == Some(128) && is_overlap_family(s))
}
```

`SYN+ACK` TTL'inden tahmin edilen başlangıç TTL'i 128 ise (Windows =
ilk-gelen-kazanır yeniden birleştirme), overlap ailesi hiç dağıtılmaz — çünkü
overlap'in beslediği çöp baytlar o yığında el sıkışmayı bozar. Bu gate hem
`assign` hem `record`'un tükenme kontrolünde aynı biçimde uygulanır, dolayısıyla
"gate yüzünden erişilemeyen adaylar" hedefi yanlışlıkla `Exhausted` yapmaz.

### 4.6 Bellek ve ölçek

| Mekanizma | Değer | Yer |
|---|---|---|
| Boşta `Probe`/passthrough hedef tahliyesi | 24 saat | `config.rs` `target_idle_evict` |
| Herhangi bir hedefin üst sınırı | 7 gün | `target_max_idle` |
| Sert hedef tavanı (en düşük değerli önce atılır) | 4096 | `max_targets` |
| Terminal geçişte skor temizliği | `compact()` | `profile/mod.rs` |
| Kalıcılaştırma filtresi | yalnızca "yeniden öğrenmesi pahalı" hedefler | `persist_worthy` (`discovery/mod.rs:449`) |

`compact()` ayrıntısı önemlidir: 166 adaylık tam tarama, hedef başına ~166
`ScoredStrategy` (her biri gömülü bir `Strategy`) tutardı; terfi/tükenme anında
yalnızca terfi eden skor korunur.

---

## 5. Başarıyı tekrar doğrulama mimarisi

### 5.1 Karar (verdict) nereden gelir

Doğrulama iki kaynaklıdır — **paket güdümlü** ve **zaman güdümlü**:

| Karar | Tetikleyici | Kaynak |
|---|---|---|
| `Success` | ClientHello sonrası sunucudan TLS `0x16` (ServerHello) veya `0x17` (app data) | `conntrack/events.rs:66` |
| `DpiReset` | ClientHello sonrası, sunucu verisinden önce gelen `RST` | aynı |
| `TlsError` | ClientHello öncesi `RST`, ya da ServerHello'dan önce `0x15` TLS alert | aynı |
| `Blackhole` | 3 ClientHello retransmit **veya** 5 sn sessizlik | `observe_outbound` + `resolve_timeout` (`events.rs:115`) |
| `Inconclusive` | Akış hiçbir şey olmadan yaşlandı | `resolve_timeout` |

Karar bir kez konur, sonraki paketler yeniden sınıflandırmaz (`set()` +
`st.outcome.is_some()` erken çıkışı) — başarılı bir el sıkışmadan sonraki normal
kapanış `RST`'inin başarıyı bozmaması bunun sayesindedir.

### 5.2 Denemenin sonuca bağlanması (attribution)

```
act_on_client_hello ──► FlowState.trial = TrialRecord { id, kind }   (engine.rs:290)
                                     │
       karar oluştu ────────────────►│
                                     ▼
        feed_discovery(target, trial, outcome, timing)               (engine.rs:410)
                                     ▼
        Discovery::record_timed ──► Scheduler::record_timed          (scheduler.rs:271)
```

Bağlama **akış bazlıdır**, dolayısıyla paralel taramada karışma olmaz: her
kararın hangi adaya ait olduğu kesindir. Kararla birlikte `VerdictTiming`
(ClientHello→karar gecikmesi + retransmit sayısı) da taşınır.

### 5.3 Terfi / düşürme kuralları

| Olay | Eşik | Etki |
|---|---:|---|
| Grid taramasından gelen adayın başarısı | `promote_after_success = 2` | `Active`, `active = sid`, `compact()` |
| Tohumlu (`DomainSibling`/`HouseStrategy`) adayın başarısı | **1** | aynı |
| Adayın başarısızlığı (`Discover`) | **1** | `tried`'a eklenir — **kalıcı eleme** |
| Aktif stratejinin başarısızlığı | `demote_after_failure = 3` | `Demoted`; `tried` temizlenir, tarama sıfırdan başlar |
| `Inconclusive` | — | `Noted`, hiçbir sayaç oynamaz |

Buradaki **asimetri bilinçli bir hız/doğruluk takasıdır**: başarı iki kez
kanıtlanmalı, başarısızlık bir kez yeterli. 166 adaylık bir uzayı makul sürede
taramanın başka yolu yok; ama maliyeti [Bulgu 2](#bulgu-2-tek-başarısızlık-kalıcı-eleme-üretir)'de.

### 5.4 Ölçülen ama kullanılmayan kalite sinyali

`StrategyQuality` (`profile/score.rs`) her başarıda şunları biriktirir:
`min_latency`, `latency_ewma` (a=1/4), `retx_free_successes`, `slow_successes`.
`looks_fast()` = "≥2 retransmit'siz başarı ve hiç yavaş başarı yok".

Bu sinyal bugün **yalnızca tohum sıralamasında** kullanılıyor; terfi kararına
girmiyor (kodda açıkça belirtilmiş: *"Timing is recorded but does not yet
influence promotion"*). Yani "çalışıyor" ile "hızlı çalışıyor" ayrımı toplanıyor
ama henüz karara dönüşmüyor — [§8](#8-öncelikli-yol-haritası)'de en olgun
iyileştirme adayı budur.

### 5.5 Oturumlar arası doğrulama sürekliliği

Kalıcı dosya (`<net_key>.json`) hedef başına `phase`, `tried`, skorlar, `active`,
`consecutive_success/failure`, `server_initial_ttl` ve `grid_size_at_exhaustion`
taşır. Yüklemede **her id canlı gride karşı tek tek doğrulanır**; hepsi varsa
tarama durumu tam geri gelir, biri bile yoksa strateji verisi düşürülür ve
yalnızca öğrenilmiş TTL korunur (`discovery/mod.rs:94`). `grid_signature`
(tüm id'ler üzerinden FNV-1a) bilgilendirme amaçlıdır; asıl karar id-alt-küme
kontrolüdür — bu, sürüm atlamalarına karşı doğru ve muhafazakâr bir tasarımdır.

---

## 6. Doğrulanmış bulgular

### Bulgu 1 — terfi sayacı hedef bazlı, aday bazlı değil

**Durum: testle üretildi (CONFIRMED).**

`ts.consecutive_success`, `TargetState` üzerinde tutulur ve **hangi adayın**
başarılı olduğuna bakılmaksızın artar (`scheduler.rs:318`); terfi ise **o anki**
`sid`'i terfi ettirir (`scheduler.rs:325-336`).

Paralel tarama tam olarak bu koşulu üretir: A ve B adayları eşzamanlı iki
bağlantıda uçuşta olsun, her biri **birer kez** başarılı olsun.

```
assign → A (in_flight)          assign → B (in_flight)
record(A, Success) → consecutive_success = 1  → Noted
record(B, Success) → consecutive_success = 2  → Promoted { strategy: B, after: 2 }
```

Geçici bir test ile çalıştırılan çıktı:

```
PROBE e1=Noted e2=Promoted { strategy: "frag@2", after: 2, via_seed: None }
PROBE promoted candidate successes=Some((1, 1))
```

Terfi eden adayın kendi skoru **1 başarı / 1 deneme**. README'nin ve kod
yorumlarının vaat ettiği "bir aday arka arkaya iki kez gerçek `ServerHello`
üretirse terfi eder" ifadesi bu yolda sağlanmıyor.

**Etki.** Yıkıcı değil — her iki aday da en az bir kez gerçekten çalışmıştır ve
yanlış seçim `demote_after_failure = 3` ile kendini düzeltir. Ama doğrulamanın
istatistiksel gücü tasarlandığının yarısına düşer ve bu, kalıcılaştırılan bir
karardır. Ayrıca sayaç sıfırlaması da hedef bazlıdır: A başarılı, B başarısız,
A yine başarılı → A hâlâ terfi edemez (B'nin başarısızlığı A'nın sayacını
sıfırladı) — yani hata her iki yöne de çalışır.

**Öneri.** Sayacı adaya taşımak yeterlidir ve `ScoredStrategy` zaten gerekli
alanları tutuyor. En küçük değişiklik: terfi koşuluna adayın **kendi** ardışık
başarısını sormak — ör. `ScoredStrategy`'ye `consecutive_success: u8` ekleyip
`note()` içinde başarıda artırıp başarısızlıkta sıfırlamak, `scheduler.rs`'te
eşiği bu alandan okumak. Hedef bazlı sayaç `Active` fazındaki
`consecutive_failure` için olduğu gibi kalabilir (orada tek strateji vardır ve
semantik doğrudur).

### Bulgu 2 — tek başarısızlık kalıcı eleme üretir

**Durum: kod okumasıyla doğrulandı.**

`Discover` fazında herhangi bir başarısızlık adayı doğrudan `ts.tried`'a yazar
(`scheduler.rs:346`) ve `tried` **diske kalıcılaştırılır** (`PersistedTarget.tried`).
Bir adayı yeniden dener hale getirmenin tek yolu, aktif stratejinin 3 kez üst
üste düşmesiyle gelen `Demoted` geçişidir (orada `ts.tried.clear()` çağrılır).

Sorun şu: `Blackhole` kararı 5 saniyelik bir zaman aşımı veya 3 retransmit'tir —
geçici bir Wi-Fi kesintisi, bir hücresel el değiştirme veya sunucu tarafı bir
gecikme, **DPI ile hiç ilgisi olmayan** bir başarısızlığı üretebilir. O anda
uçuşta olan aday, o hedef için kalıcı olarak elenir ve bu eleme diske yazılır.
Grid sıralaması olasılığa göre olduğundan, kayıp genellikle **en iyi adaylardan
biridir** (taramanın başındakiler).

**Öneri.** İki kademeli bir eleme: ilk başarısızlıkta adayı `tried` yerine bir
"karantina" listesine koymak (gride geri dönmeden önce diğer adaylar denensin),
tarama tükenmeye yaklaştığında karantinadakileri bir kez daha denemek. Alternatif
olarak `Blackhole` ile `DpiReset`'i ayırmak: `DpiReset` DPI'a özgüdür ve tek
gözlem ikna edicidir; `Blackhole` ise gürültülüdür ve ikinci bir gözlem hak eder.

### Bulgu 3 — `Success` tanımı "el sıkışma başladı" demektir

**Durum: kod okumasıyla doğrulandı.**

`Success`, sunucudan gelen ilk `0x16` veya `0x17` TLS kaydıdır. Bu, el
sıkışmanın **tamamlandığını** veya veri aktığını garanti etmez. Pratikte bu
büyük olasılıkla yeterlidir (SNI'ye dayalı bir sansürcü ClientHello'yu geçirdiyse
iş bitmiştir), ancak iki senaryo boşta kalır: (a) ServerHello sonrası bir üst
katman sıfırlaması, (b) bazı ortamlarda gözlenen enjekte edilmiş sahte
TLS yanıtları. `StrategyQuality`'nin `retx` sayacı bu tür "başarılı ama sancılı"
durumları zaten görüyor; onu `looks_fast` dışında da kullanmak mümkün.

### Bulgu 4 — zamanlama sabitleri tutarlı

**Durum: kod okumasıyla doğrulandı — sorun yok, teyit amaçlı.**

`in_flight_ttl = 15 sn`, `verdict_timeout = 5 sn` ve tick periyodu 500 ms'dir.
Yani bir karar en geç ~5.5 sn'de üretilir ve `in_flight` girdisi her zaman
karardan **sonra** düşer; bir aday hiçbir zaman "hâlâ uçuşta" sanılırken sessizce
kaybolmaz. `in_flight_ttl`'in `verdict_timeout`'u rahatça aşması gerektiği kod
yorumunda da şart koşulmuş ve varsayılanlar bunu sağlıyor.

---

## 7. Kapsam boşlukları ve riskler

| Konu | Mevcut durum | Risk |
|---|---|---|
| **QUIC / HTTP-3** | Filtre tanımlı ve derleniyor, ama `DROP` handle'ı motorda açılmıyor → QUIC olduğu gibi geçiyor | Sansürcü QUIC üzerinde de SNI engelliyorsa tarayıcı TCP'ye düşene kadar site açılmaz — kullanıcıya "çalışmıyor" gibi görünür. En yüksek etkili açık uç. |
| **DNS** | `dns_upstream` alanı ve `udp/53` filtre maddesi var, CLI'ya bağlanmamış | DNS zehirlenmesi varsa Bosphorus'un yaptığı hiçbir şey yetmez; `blockcheck` bu ayrımı yapabiliyor |
| **ECH** | Açık SNI yoksa hedef oluşturulmaz, dokunulmaz | Doğru karar; ama ECH yayıldıkça motorun anahtarı (SNI) kaybolur — uzun vadeli mimari soru |
| **Port kapsamı** | 443 + Cloudflare alternatifleri (2053/2083/2087/2096/8443) | Bilinçli daraltma; başka portta TLS koşan servisler kapsanmaz |
| **Platform** | Yalnızca Windows x64 | Çekirdek taşınabilir yazılmış — Linux `nfqueue` arka ucu düşük maliyetli bir genişleme olurdu |
| **Tarama hızı** | Uygulamanın yeniden deneme hızına bağlı | Tek bağlantılı uygulamalarda 166 aday uzun sürer; opsiyonel bir "aktif tarama" modu (kullanıcı onaylı) bunu kırabilir |

---

## 8. Öncelikli yol haritası

| # | İş | Neden | Büyüklük |
|---|---|---|---|
| 1 | **Terfi sayacını adaya taşı** ([Bulgu 1](#bulgu-1-terfi-sayacı-hedef-bazlı-aday-bazlı-değil)) | Doğrulama şu an tasarlanan güvenceyi vermiyor; paralel tarama bunu tetikliyor | Küçük (`ScoredStrategy` + `scheduler.rs`, mevcut testler korunur) |
| 2 | **Karantina / ikinci şans** ([Bulgu 2](#bulgu-2-tek-başarısızlık-kalıcı-eleme-üretir)) | Geçici ağ hatası en iyi adayı kalıcı olarak eliyor ve bu diske yazılıyor | Orta |
| 3 | **QUIC DROP handle'ını aç** | Tanımlı ama bağlı değil; kullanıcıya görünen en büyük boşluk | Orta |
| 4 | **`StrategyQuality`'yi terfiye bağla** | Veri zaten toplanıyor; "çalışan" yerine "hızlı çalışan" seçilebilir | Küçük–orta |
| 5 | **`DpiReset` ve `Blackhole` için farklı ağırlıklar** | Biri DPI'a özgü ve kesin, diğeri gürültülü — aynı muameleyi hak etmiyorlar | Küçük |
| 6 | **Public Suffix List** (tohumlama için) | Kaba eTLD+1 sezgiseli `co.uk` dışı çok seviyeli son eklerde yanılır | Küçük |

---

## Ek: doğrulama yöntemi

- Çekirdek test paketi bu incelemede Linux üzerinde çalıştırıldı:
  `cargo test -p bosphorus-core` → **147 test, hepsi geçti**.
- Grid boyutu iddiası (166 / 174) ve aday sıralaması, `DefaultGenerator`'a
  eklenen geçici bir test ile ölçüldü; ölçüm sonrası geçici test kaldırıldı.
- [Bulgu 1](#bulgu-1-terfi-sayacı-hedef-bazlı-aday-bazlı-değil), `Scheduler`
  üzerine yazılan geçici bir senaryo testiyle üretildi (iki eşzamanlı aday, her
  biri bir başarı); çıktı bölümde aynen aktarılmıştır. Geçici test kaldırıldı —
  bu değişiklik depoda hiçbir kaynak dosyayı değiştirmez.

## Kaynaklar (karşılaştırma bölümü)

- [zapret — readme.en.md](https://github.com/bol-van/zapret/blob/master/docs/readme.en.md)
- [zapret — blockcheck.sh](https://github.com/bol-van/zapret/blob/master/blockcheck.sh)
- [blockcheck Strategy Testing (DeepWiki)](https://deepwiki.com/bol-van/zapret/6.1-using-blockcheck.sh)
- [ByeDPI — README](https://github.com/hufrea/byedpi/blob/main/README.md)
- [hufrea/byedpi (DeepWiki)](https://deepwiki.com/hufrea/byedpi)
- [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)
