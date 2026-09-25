Pod::Spec.new do |s|
  s.name             = 'mobile_hardening_kit'
  s.version          = '0.1.0'
  s.summary          = 'Client-side mobile integrity and display signals for Flutter apps.'
  s.description      = 'Native Android and iOS integrity and display signal collectors.'
  s.homepage         = 'https://github.com/iqbal-mekari/mobile-hardening-kit'
  s.license          = { :file => '../LICENSE' }
  s.author           = 'Mobile Hardening Kit contributors'
  s.source           = { :git => 'git@github.com:iqbal-mekari/mobile-hardening-kit.git', :tag => s.version.to_s }
  s.source_files = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '13.0'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'
end
