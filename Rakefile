MODNAME="mod_reproxy"
ENV['LTFLAGS'] = "--tag=CC"

rule '.la' => ['.c'] do |t|
  sh "apxs -c #{t.source}"
end

task :default => "#{MODNAME}.la"

task :install => :default do
  sh "sudo apxs -i #{MODNAME}.la"
end

task :restart do
  sh "sudo /opt/local/apache2/bin/apachectl restart"
end

task :all => [:install, :restart]

task :clean do
  globs = %w(.libs *.la *.lo *.o *.slo)
  files = globs.map { |pat| Dir[pat] }.flatten

  if files.any?
    rm_rf(files)
  else
    puts "nothing to clean"
  end
end
