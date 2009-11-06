MODNAME="mod_reproxy"
ENV['LTFLAGS'] = "--tag=CC"

rule '.la' => ['.c'] do |t|
  sh "apxs -c #{t.source}"
end

desc "Build #{MODNAME}"
task :default => "#{MODNAME}.la"

desc "Install #{MODNAME}"
task :install => :default do
  sh "sudo apxs -i #{MODNAME}.la"
end

desc "Restart apache"
task :restart do
  sh "sudo -p 'sudo password:' apachectl restart"
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
