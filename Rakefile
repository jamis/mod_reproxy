MODNAME="mod_reproxy"
#ENV['LTFLAGS'] = "--tag=CC"
APXS=ENV['APXS'] || 'apxs'
APACHECTL=ENV['APACHECTL'] || 'apachectl'

rule '.la' => ['.c'] do |t|
  sh "#{APXS} -c -Wc,-g #{t.source}"
end

desc "Build #{MODNAME}"
task :default => "#{MODNAME}.la"

desc "Install #{MODNAME}"
task :install => :default do
  sh "sudo #{APXS} -i #{MODNAME}.la"
end

desc "Restart apache"
task :restart do
  sh "sudo -p 'sudo password:' #{APACHECTL} restart"
end

desc "Build and install #{MODNAME}, and restart apache"
task :all => [:install, :restart]

desc "Remove all generated artifacts"
task :clean do
  globs = %w(.libs *.la *.lo *.o *.slo)
  files = globs.map { |pat| Dir[pat] }.flatten

  if files.any?
    rm_rf(files)
  else
    puts "nothing to clean"
  end
end
