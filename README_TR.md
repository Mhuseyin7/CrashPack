# CrashPack

CrashPack, kullanıcı makinesindeki sorunlar için hassas verileri temizlenmiş yerel destek paketleri üretir. Otomatik yükleme yapmaz, tüm makineyi taramaz ve yalnızca yapılandırmada açıkça tanımlanan kaynakları toplar.

Başlamak için `cargo run -- init` çalıştırın, oluşturulan `crashpack.yml` dosyasını dikkatle gözden geçirin ve ardından `cargo run -- preview` ile planı kontrol edin. Paket oluşturmak için `cargo run -- collect`, manifesti görmek için `inspect`, sağlama toplamlarını doğrulamak için `verify` kullanın.
