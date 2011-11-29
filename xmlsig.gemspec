Gem::Specification.new do |s|
  s.name = 'xmlsig'
  s.summary = 'XML Signature methods for ruby'
  s.description = 'A gem that wraps up Verisign\'s XMLSIG for Dynamic Languages (http://xmlsig.sourceforge.net)'
  s.authors  = ['Joe Lind']
  s.email    = ['joe@terriblelabs.com']
  s.homepage = 'http://github.com/terriblelabs/xmlsig'

  s.version = '0.0.2'
  s.date = '2011-11-29'

  s.extensions    = ["ext/xmlsig/extconf.rb"]
  s.require_paths = ["ext", "lib"]

  s.files = Dir.glob('lib/**/*.rb') +
            Dir.glob('ext/**/*.{c,h,rb,i,cpp}')

  s.extra_rdoc_files = ['README.rdoc']
end
