---
feature: file-crypto
status: delivered
updated: 2026-09-28
branch: feature/file-crypto
commits: 91d1eaa..369d938
---

# 鏂囦欢鍔犲瘑宸ュ叿锛?yuexuan 瀹瑰櫒锛?
## Report

**What was built** — Windows 绿色版单文件加密工具 `YuexuanCrypto.exe`（.NET 9 WPF）。可将多个文件/文件夹拖入打包为自定义 `.yuexuan` 容器；解密需同时具备用户密码与软件内置密钥因子。容器使用 YXENC01 魔数、AES-256-GCM 1MiB 分块流式加解密、流 MAC 防篡改。界面含进度/速度/ETA、弱密码警告（含常见弱口令）、冲突覆盖/跳过/改名对话框（可全部应用）、取消清理、关于页（作者 yuexuan）、显示密码、快捷键、完成后打开文件夹、拖入 .yuexuan 自动进解密。不联网、无遥测；源文件永不修改。

**Optimization round (P0-P2)** — Format v2 writes Argon2id KDF params into the header (decrypt still reads v1 PBKDF2); software factor hardened (4-way XOR + AES restore + label mix); encrypt aborts if source size changes mid-read; PathGuard rejects junction/symlink reparse points; decrypt stages to `.part` and commits only after stream-MAC verification; removed dead `headerNonce`/`GetCurrent`.

**Verification** — custom test runner 21/21 PASS (Argon2id roundtrip, KDF params persisted, overwrite protection, conflict skip, cancel cleanup, Chinese names/empty dir/empty file, tamper/truncate/fake magic); self-contained `dist/YuexuanCrypto.exe` ~59MB published; GUI launch smoke PASS. Independent review first FAIL (decrypt overwrite data loss), fixed then PASS_WITH_MINOR; further hardened format/UX/tests.

**Journey log** — NuGet restore broken in env, used hand-written project.assets.json + --no-restore and downloaded runtime pack / Isopoh Argon2 from nuget.org; `git worktree add` blocked by sandbox, used in-place feature branch; review found decrypt FileMode.Create data-loss bug, fixed via .part staging + deferred commit; Argon2.Hash returns SecureArray and must read `.Buffer`.

## [S1] Problem

鐢ㄦ埛闇€瑕佷竴娆?Windows 鏈湴鏂囦欢鍔犲瘑宸ュ叿锛氬皢澶氫釜鏂囦欢/鏂囦欢澶规墦鍖呮垚**鍙湁閰嶅杞欢 + 姝ｇ‘瀵嗙爜**鎵嶈兘瑙ｅ紑鐨勮嚜瀹氫箟瀹瑰櫒锛坄.yuexuan`锛夈€傚父瑙佽В鍘?鍔犲瘑杞欢蹇呴』鏃犳硶璇嗗埆璇ユ牸寮忋€傚悓鏃惰绋冲畾澶勭悊鏁板崄 GB 绾уぇ鏂囦欢锛堟亽瀹氬唴瀛樸€佸彲鏄剧ず杩涘害銆佸彲鍙栨秷锛夛紝鐣岄潰鐜颁唬绠€娲侊紝浠ｇ爜绋冲仴涓旀棤閬ユ祴銆佹棤闅愮澶栨硠銆備綔鑰呮爣璇?yuexuan 浣庤皟鍑虹幇鍦ㄧ晫闈㈣钀姐€?
## [S2] Design

### S2.1 浜у搧褰㈡€?
| 椤?| 鍐冲畾 |
|---|---|
| 鎶€鏈爤 | .NET 9 + WPF锛堜笌宸茶 SDK/妗岄潰杩愯鏃跺榻愶級 |
| 鍙戝竷 | 鍗曟枃浠惰嚜鍖呭惈 `exe`锛坵in-x64锛屽弻鍑诲嵆鐢紝涓嶄緷璧栨湰鏈?.NET锛?|
| 璇█ | 绠€浣撲腑鏂囩晫闈?|
| 瑙嗚 | 鐜颁唬绠€娲佹祬鑹蹭富鐣岄潰锛屽ぇ鐣欑櫧銆佸崱鐗囧紡銆佹竻鏅板眰绾?|
| 鏍囪瘑 | 涓荤晫闈㈢姸鎬佽钀藉皬瀛?`yuexuan`锛涖€屽叧浜庛€嶉〉浣滆€咃紱**涓嶅啓鍏ュ鍣ㄦ槑鏂?* |
| 鍛藉悕 | 鏃犱骇鍝佸悕锛涚獥鍙ｆ爣棰樸€屾枃浠跺姞瀵嗐€?|
| 鑼冨洿 | 浠?Windows锛涗笉娉ㄥ唽鏂囦欢鍏宠仈锛涗笉鑱旂綉锛涙棤閬ユ祴 |

### S2.2 鐢ㄦ埛鍙琛屼负

**鍔犲瘑锛堟墦鍖咃級**

1. 鎷栧叆澶氫釜鏂囦欢鍜?鎴栨枃浠跺す锛屾垨浣跨敤銆屾坊鍔犳枃浠?/ 娣诲姞鏂囦欢澶广€嶆寜閽€?2. 璁剧疆瀵嗙爜锛堜袱娆＄‘璁わ級锛涘彲閫夊～銆屽瘑鐮佹彁绀恒€嶏紱寮卞瘑鐮佷粎璀﹀憡涓嶉樆鏂€?3. 閫夋嫨杈撳嚭 `.yuexuan` 璺緞锛?*淇濈暀鍘熸枃浠?*锛屼笉淇敼銆佷笉鍒犻櫎婧愩€?4. 杩涘害锛氱櫨鍒嗘瘮銆佸凡澶勭悊/鎬诲瓧鑺傘€佸疄鏃堕€熷害銆佸凡鐢?棰勮鏃堕棿銆佸綋鍓嶉樁娈垫枃妗堛€?5. 鍙殢鏃跺彇娑堬紱鍙栨秷鎴栧け璐ユ椂鍒犻櫎鏈畬鎴愮殑杈撳嚭涓存椂鏂囦欢锛屾簮鏂囦欢淇濇寔涓嶅彉銆?6. 鎵瑰鐞嗕腑鍗曟枃浠舵棤娉曡鍙栵紙鍗犵敤/鏉冮檺锛夛細鍏堝皾璇曡嚜鍔ㄨВ鍐筹紙鐭殏閲嶈瘯銆佸繀瑕佹椂鎻愮ず鍏抽棴鍗犵敤鏂癸級锛涗粛澶辫触鍒欑粰鍑烘槑纭師鍥犲苟**鍥炴粴鍒板姞瀵嗗墠鐘舵€?*锛堜笉鐢熸垚娈嬬己瀹瑰櫒锛屼笉鏀瑰姩婧愶級銆?
**瑙ｅ瘑锛堣繕鍘燂級**

1. 鍦ㄨ蒋浠跺唴閫夋嫨 `.yuexuan`锛堟嫋鎷芥垨鎸夐挳锛夛紝杈撳叆瀵嗙爜銆?2. 閫夋嫨鐩爣鏂囦欢澶癸紝灏嗗鍣ㄥ唴鐩綍鏍戝畬鏁磋繕鍘熴€?3. 鍚屽悕鍐茬獊锛氳闂€岃鐩?/ 璺宠繃 / 鑷姩鏀瑰悕銆嶏紝鎵归噺鍦烘櫙鍙€屽叏閮ㄥ簲鐢ㄣ€嶃€?4. 瑙ｅ瘑澶辫触锛堝瘑鐮侀敊/鎹熷潖/绡℃敼锛夌粰鍑哄垎灞傞敊璇枃妗堬紝涓嶈В鍑哄崐鎴贡鐮佺洰褰曘€?5. 鍙彇娑堬紱鍙栨秷娓呯悊涓存椂浜х墿銆?
**瀵嗙爜涓庢彁绀?*

- 瀵嗙爜绛栫暐锛氫笉闄愬埗闀垮害/瀛楃闆嗭紱鐣岄潰寮哄害鎻愮ず + 寮卞瘑鐮佽鍛娿€?- 鎻愮ず璇嶅彲閫夛紱瀛樺湪瀹瑰櫒鍐呭苟鍋氳交搴︽贩娣嗭紙闈炴槑鏂囷級锛岃В瀵嗗墠鍙敱鏈蒋浠跺睍绀恒€?- 鍏ㄦ祦绋嬪己璋冦€屽繕璁板瘑鐮佹棤娉曟壘鍥炪€嶃€?
### S2.3 瀹瑰櫒鏍煎紡 `.yuexuan`

鑷畾涔変簩杩涘埗甯冨眬锛堝皬绔級锛?*涓嶆槸** ZIP/7z/PeaZip/openssl 鏍煎紡銆傞瓟鏁颁笌甯冨眬淇濊瘉甯歌宸ュ叿鏃犳硶璇嗗埆銆?
```
+-------------------+
| Magic "YXENC01"   |  7 bytes ASCII
| Version u16 = 1   |  2 bytes
| HeaderLen u32     |  4 bytes
+-------------------+
| EncryptedHeader   |  HeaderLen bytes (AES-256-GCM, associated data = Magic||Version)
|   nonce 12B       |
|   ct||tag         |
+-------------------+
| ChunkStream       |  瑙佷笅
+-------------------+
| Footer            |
|   total_chunks u64|
|   stream_mac 32B  |  HMAC-SHA256(software_bound_tag_key, chunk_cipher_digest)
+-------------------+
```

**EncryptedHeader 鏄庢枃锛圝SON UTF-8锛岃В瀵嗗悗浠呭瓨鍐呭瓨锛?*

```json
{
  "hint": "<optional, already lightly obfuscated>",
  "created_utc": "...",
  "entries": [
    {"type":"dir","path":"docs/notes"},
    {"type":"file","path":"docs/a.txt","size":123,"chunk_count":1}
  ]
}
```

- 鐩稿璺緞浣跨敤 `/` 鍒嗛殧锛岃鑼冨寲鍚庡瓨鍌紱绂佹 `..` 涓庣粷瀵圭洏绗︼紙瑙ｅ瘑绔簩娆℃牎楠岋紝闃?zip-slip锛夈€?- 鏀寔绌虹洰褰曘€佷腑鏂?绌烘牸/鐗规畩瀛楃鏂囦欢鍚嶃€乄indows 闀胯矾寰勶紙`\\?\` 璇诲啓锛夈€?- 涓嶅帇缂╋紝鍙姞瀵嗭紙鍐呭瀛楄妭鍘熸牱杩涘叆鍒嗗潡娴侊級銆?
**ChunkStream锛堝ぇ鏂囦欢鍙嬪ソ锛?*

- 鍒嗗潡澶у皬 1 MiB锛堝父閲?`ChunkSize = 1 << 20`锛夈€?- 姣忓潡锛歚nonce(12) || AES-256-GCM-ciphertext || tag(16)`锛屾槑鏂?鈮?1 MiB锛涙渶鍚庝竴鍧楀彲鐭€?- 姣忔枃浠剁嫭绔嬩粠 chunk index 0 寮€濮嬶紱鏂囦欢鎸?entries 椤哄簭涓茶仈銆?- 璇绘枃浠朵笌鍐欏鍣ㄥ潎涓洪『搴忔祦寮?I/O锛屽唴瀛樺崰鐢ㄤ笌鏂囦欢澶у皬鏃犲叧锛堜粎褰撳墠鍧楃紦鍐诧級銆?- 姣忓潡瀵嗘枃閫愬潡鏇存柊 `stream_mac`锛汧ooter 鍐嶅啓鍏ユ€诲潡鏁颁笌 MAC锛屾埅鏂?鎷兼帴鍙娴嬨€?
### S2.4 瀵嗛挜浣撶郴锛堝弻閲嶄繚鎶わ級

瑙ｅ瘑蹇呴』鍚屾椂鍏峰锛?*(1) 鐢ㄦ埛瀵嗙爜 (2) 鏈蒋浠跺唴缃洜瀛?*銆傜己浠讳竴涓嶅彲瑙ｃ€?
```
password_bytes = UTF8(鐢ㄦ埛瀵嗙爜)          // 浣跨敤鍚庣珛鍗虫竻闆?salt           = Header 涓殢鏈?16B锛堥殢鏂囦欢锛?pwd_key        = Argon2id(password_bytes, salt, m=64MiB, t=3, p=4, 32B)
software_factor= 缂栬瘧杩涚▼搴忛泦鐨?32B 绉樺瘑锛堝垎鏁ｅ瓨鍌?+ 杩愯鏃舵嫾瑁咃紝閬垮厤鍗曞瓧绗︿覆甯搁噺锛?wrap_key       = HKDF-SHA256(ikm=pwd_key || software_factor, salt, info="YXENC-WRAP-v1", 32B)
file_key       = 闅忔満 32B锛堝姞瀵嗘椂鐢熸垚锛?wrapped_key    = AES-256-GCM(wrap_key, file_key)     // 鏀惧叆 EncryptedHeader 鏄庢枃缁撴瀯鏃佺殑鐙珛瀛楁
header_key     = HKDF-SHA256(file_key, salt, "YXENC-HDR-v1", 32B)
chunk_key      = HKDF-SHA256(file_key, salt, "YXENC-CHUNK-v1", 32B)
tag_key        = HKDF-SHA256(file_key, salt, "YXENC-TAG-v1", 32B)
```

- `EncryptedHeader` 鐢?`header_key` 鍔犲瘑锛涜矾寰勩€佸ぇ灏忋€佹彁绀恒€乪ntry 鍒楄〃瀵瑰涓嶅彲瑙併€?- 鏃?`software_factor` 鏃讹紝鍗充娇瀵嗙爜姝ｇ‘涔熸棤娉曚粠 `wrapped_key` 杩樺師 `file_key`銆?- 甯歌宸ュ叿锛氭棤榄旀暟鍖归厤銆佹棤鏍囧噯瀹瑰櫒缁撴瀯锛屾棤娉曡瘑鍒€?
**Argon2id 鍙傛暟**锛歚m=64MiB, t=3, p=4`锛堝湪浜や簰鍙帴鍙楀欢杩熶笌鎶?GPU 鐮磋В闂存姌涓級銆傚疄鐜板彲鐢ㄧ函鎵樼搴擄紱鑻ョ幆澧冮檺鍒跺垯閫€鍖栦负 `PBKDF2-HMAC-SHA256` 杩唬 鈮?600_000 骞跺湪浠ｇ爜甯搁噺鍖烘敞鏄庯紙楠屾敹浠ュ彲瑙?鍙岄噸淇濇姢涓哄噯锛夈€?
**瀵嗙爜鎻愮ず娣锋穯**锛歚hint_storage = XOR(hint_utf8, HKDF(software_factor, "HINT"))`锛岄潪鏄庢枃鍙壂锛涗粎鏈蒋浠跺彲杩樺師灞曠ず銆?*涓嶅緱**鎶婂瘑鐮佹湰浣撳啓鍏ユ彁绀烘垨鏃ュ織銆?
### S2.5 妯″潡鍒掑垎

```
src/YuexuanCrypto.Core/          // 鏃?UI锛屽彲鍗曟祴
  Crypto/   KeyDerivation, SoftwareFactor, ChunkCipher, HeaderCipher, Hashing
  Format/   ContainerReader, ContainerWriter, Manifest, FormatConstants
  Pipeline/ EncryptPipeline, DecryptPipeline, ProgressReport, ConflictPolicy
  Security/ PathGuard, SensitiveBuffer, Guard

src/YuexuanCrypto.App/           // WPF
  ViewModels/ MainWindowViewModel, ...
  Views/ MainWindow, AboutDialog, ConflictDialog
  Services/ DialogService, Theme

tests/YuexuanCrypto.Core.Tests/
```

**绠￠亾濂戠害锛堢ǔ瀹氾級**

- `EncryptPipeline.EncryptAsync(EncryptRequest, IProgress<ProgressReport>, CancellationToken) 鈫?EncryptResult`
- `DecryptPipeline.DecryptAsync(DecryptRequest, IProgress<ProgressReport>, CancellationToken) 鈫?DecryptResult`
- `ProgressReport { BytesDone, BytesTotal, FilesDone, FilesTotal, Stage, BytesPerSecond, Elapsed, Eta }`
- 澶辫触锛氭姏鍑?杩斿洖棰嗗煙閿欒锛坄WrongPassword`, `Corrupted`, `IntegrityFailed`, `IoError`, `Cancelled`, `PathUnsafe`鈥︼級锛孶I 鏄犲皠涓轰腑鏂囨枃妗堛€?- 鎵€鏈夎緭鍑哄厛鍐?`*.yuexuan.part`锛堟垨鐩爣鐩綍 `*.part`锛夛紝鎴愬姛鍚庡師瀛愭浛鎹负鏈€缁堝悕锛涘け璐?鍙栨秷鍒犻櫎 `.part`銆?
### S2.6 绋冲仴涓庨殣绉?
- 鏈煡/鎹熷潖杈撳叆锛氳В鏋愬け璐ヨ繑鍥?`Corrupted`锛屼笉宕╂簝銆?- 璺緞鏍￠獙锛氭嫆缁?`..`銆佺粷瀵硅矾寰勩€佺洏绗︺€佷繚鐣欒澶囧悕锛涜В瀵嗙洰鏍囧啿绐佹樉寮忚闂€?- 涓嶈仈缃戙€佷笉涓婁紶銆佹棤閬ユ祴锛涙棩蹇椾粎鎺у埗鍙?鍙€夋湰鍦拌瘖鏂紑鍏充笖榛樿鍏筹紱缁濅笉璁板綍瀵嗙爜銆佸瘑閽ャ€佹彁绀哄師鏂囥€佹枃浠跺唴瀹广€?- 瀵嗙爜 `PasswordBox` 鈫?灏藉揩杞叆鍙竻闆剁紦鍐插尯锛岀敤鍚?`CryptographicOperations.ZeroMemory`銆?- 寮傚父鍏ㄥ眬鍏滃簳锛氬睍绀洪敊璇紝涓嶉棯閫€锛涜皟璇曚俊鎭笉鍚晱鎰熸暟鎹€?
### S2.7 楠屾敹涓庢祴璇曡竟鐣?
- 鏍稿績搴撳崟鍏冩祴璇曪細寰€杩旓紙绌烘枃浠?绌虹洰褰?涓枃鍚?澶氭枃浠讹級銆侀敊璇瘑鐮併€佺鏀瑰瘑鏂囥€佹埅鏂€佸亣榄旀暟銆佽矾寰勭┛瓒娿€佽繘搴﹀瓧鑺備竴鑷存€с€?- 澶ф枃浠讹細浣跨敤绋€鐤?涓存椂澶ф枃浠讹紙濡?2鈥? GiB锛夊仛娴佸紡寰€杩斿啋鐑燂紙CI 鍙噺鍒?256 MiB锛夈€?- UI锛氭嫋鎷藉姞瀵嗏啋瑙ｅ瘑鎵嬪姩璧伴€氾紱鍙栨秷鍚庢棤 `.part` 娈嬬暀銆?
## [S3] Out of Scope

- 鍘嬬缉銆佸垎鍗枫€佸閲忓浠姐€佷簯鍚屾
- 绯荤粺鍙抽敭鑿滃崟 / 鏂囦欢鍏宠仈 / 瀹夎鍣?- 澶氱敤鎴?璇佷功/鏅鸿兘鍗?TPM 缁戝畾銆佹寜鏈哄櫒閿佸畾
- macOS/Linux銆佺Щ鍔ㄧ
- 瀵嗙爜鎵惧洖銆佸悗闂ㄣ€佸瘑閽ユ墭绠?- 鏆楄壊涓婚瀹屾暣閫傞厤锛堝彲鐣欐祬鑹蹭负涓伙級
- CLI 鍙屽叆鍙ｏ紙浠?GUI锛?
## Tasks

- [x] T1: 瑙ｅ喅鏂规楠ㄦ灦涓庡伐绋嬭缃?鈥?acceptance: `dotnet build` 鎴愬姛锛孋ore/App/Tests 椤圭洰寮曠敤姝ｇ‘锛宍SoftwareFactor` 鍒嗘暎瀛樺偍鏃犳槑鏂囨暣涓?(covers: S2.1, S2.5)
- [x] T2: 瀵嗛挜娲剧敓涓庡鍣ㄦ牸寮忓父閲?鈥?acceptance: Argon2id锛堟垨 PBKDF2 閫€鍖栵級+ HKDF + wrapped file_key 鍙崟娴嬪線杩旓紱FormatConstants 榄旀暟/鐗堟湰鍥哄畾 (covers: S2.3, S2.4; depends: T1)
- [x] T3: 鍒嗗潡 AEAD 璇诲啓涓庢祦 MAC 鈥?acceptance: 闅忔満鏁版嵁鍒嗗潡寰€杩斾竴鑷达紱绡℃敼浠讳竴瀛楄妭瑙ｅ瘑鎶?IntegrityFailed/Corrupted (covers: S2.3, S2.4; depends: T2)
- [x] T4: Manifest/璺緞闃叉姢涓?EncryptPipeline 鈥?acceptance: 澶氭枃浠?绌虹洰褰曟墦鍖呮垚鍔燂紱`..` 璺緞鎷掔粷锛涘け璐?鍙栨秷鍒犻櫎 `.part` 涓旀簮鏂囦欢鏈敼鍔?(covers: S2.2, S2.3, S2.6; depends: T3)
- [x] T5: DecryptPipeline 涓庡啿绐佺瓥鐣?鈥?acceptance: 杩樺師鐩綍鏍戞纭紱瀵嗙爜閿?鎹熷潖鍒嗗眰鎶ラ敊锛涜鐩?璺宠繃/鏀瑰悕鍙祴 (covers: S2.2, S2.6; depends: T4)
- [x] T6: 鏍稿績搴撴祴璇曞浠?鈥?acceptance: `dotnet test` 鍏ㄧ豢锛岃鐩栧線杩?閿欒瀵嗙爜/绡℃敼/鎴柇/闀胯矾寰勪笌涓枃鍚?(covers: S2.7; depends: T5)
- [x] T7: WPF 涓荤晫闈笌鎷栨嫿鎵归噺 鈥?acceptance: 鍙嫋鍏ユ枃浠?鏂囦欢澶广€佽瀵嗙爜涓庢彁绀恒€侀€夎緭鍑猴紱寮卞瘑鐮佽鍛婏紱鐣岄潰瑙掕惤 yuexuan (covers: S2.1, S2.2; depends: T5)
- [x] T8: 杩涘害/鍙栨秷/閿欒鎭㈠ UI 鈥?acceptance: 杩涘害鍚櫨鍒嗘瘮/閫熷害/宸茬敤棰勮锛涘彇娑堟棤娈嬬暀锛涘崰鐢ㄦ枃浠剁粰鍑哄師鍥犲苟鍥炴粴 (covers: S2.2; depends: T7)
- [x] T9: 瑙ｅ瘑 UI 涓庡啿绐佸璇濇 鈥?acceptance: 閫夊鍣?瀵嗙爜/鐩爣鐩綍锛涘啿绐佷笁閫変竴鍙€屽叏閮ㄥ簲鐢ㄣ€?(covers: S2.2; depends: T7)
- [x] T10: 鍗曟枃浠跺彂甯冧笌绔埌绔獙璇?鈥?acceptance: `dotnet publish` 浜у嚭鍙弻鍑昏繍琛岀殑鑷寘鍚?exe锛涙墜宸ュ姞瀵嗏啋鎷疯礉鍒版棤 SDK 鐜鎬濊矾涓嬭В瀵嗘垚鍔燂紱娴嬭瘯鍛戒护涓庣粨鏋滃啓鍏?Report (covers: S2.1, S2.7; depends: T6, T8, T9)

