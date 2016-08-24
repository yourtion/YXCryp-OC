Pod::Spec.new do |s|

  s.name         = "YXCryp"
  s.version      = "0.1.0"
  s.summary      = "Objdctive-C 实现常用加解密功能库。"

  s.description  = <<-DESC
                    Objdctive-C 实现常用加解密功能库。

                      - `AES256` 加密解密
                      - `SHA256`、`SHA1`、`MD5` 哈希计算
                      - `HEX` 转换
                      - `Base64` 编码解码

                  DESC

  s.homepage     = "https://github.com/yourtion/YXCryp-OC"
  s.license      = "MIT"
  s.author       = { "Yourtion" => "yourtion@gmail.com" }
  s.source       = { :git => "https://github.com/yourtion/YXCryp-OC.git", :tag => s.version  }
  s.source_files = "YXCryp"
  
  s.ios.deployment_target = '8.0'
  s.osx.deployment_target = '10.10'
  
  s.frameworks  = "Foundation"
  s.requires_arc = true

end
