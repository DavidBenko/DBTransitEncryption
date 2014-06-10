Pod::Spec.new do |s|
  s.name             = "ObjectiveTLS"
  s.version          = "0.1.0"
  s.summary          = "Encryption for data in transit; ObjectiveTLS will secure data for transit similar to the handshake protocol of TLS."
  s.description      = <<-DESC
Transport Layer Security for securing data payloads in Objective-C. An easy way to secure data by providing a symmetric key for that transaction. Keys are generated on the fly and every message will have a new key.
                       DESC
  s.homepage         = "https://github.com/DavidBenko/Objective-TLS"
  s.license          = 'MIT'
  s.author           = { "David Benko" => "dbenko@prndl.us" }
  s.source           = { :git => "https://github.com/DavidBenko/Objective-TLS.git", :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/davidwbenko'

  s.platform     = :ios
  s.requires_arc = true

  s.source_files = 'ObjectiveTLS'
end
