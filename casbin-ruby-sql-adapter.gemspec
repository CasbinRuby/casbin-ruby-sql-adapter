# frozen_string_literal: true

$LOAD_PATH.push File.expand_path('lib', __dir__)
require 'casbin-ruby-sql-adapter/version'

Gem::Specification.new do |s|
  s.name        = 'casbin-ruby-sql-adapter'
  s.version     = CasbinRubySqlAdapter::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ['Igor Kutyavin']
  s.email       = ['konayre@evrone.com']
  s.homepage    = 'https://github.com/evrone/casbin-ruby-sql-adapter'
  s.licenses    = ['Apache License 2.0']
  s.description = 'SQl adapter for Ruby'
  s.summary     = 'SQl adapter in Ruby'
  s.files = %w[README.md] + Dir.glob(File.join('lib', '**', '*.rb'))
  s.test_files = Dir.glob(File.join('spec', '**', '*.rb'))
  s.required_ruby_version = '>= 2.5.0'

  s.add_dependency 'casbin-ruby'
  s.add_dependency 'sequel', '>= 5.42'

  s.add_development_dependency 'rspec', '~> 3.10'
  s.add_development_dependency 'rubocop', '>= 1.8'
  s.add_development_dependency 'rubocop-rspec'
  s.add_development_dependency 'sqlite3'
end
