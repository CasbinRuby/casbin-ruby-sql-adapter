Sql Adapter for Ruby Casbin
====

Sql Adapter is the [Sequel](http://sequel.jeremyevans.net/) adapter for [Ruby Casbin](https://github.com/CasbinRuby/casbin-ruby). With this library, Casbin can load policy from Sequel supported database or save policy to it.

## Installation

```
gem 'casbin-ruby-sql-adapter'
```

## Simple Example

```ruby
require 'casbin-ruby'
require 'casbin-ruby-sql-adapter'

adapter = CasbinRubySqlAdapter::Adapter.new(db_url: 'sqlite:///test.db')

e = Casbin::Enforcer.new('path/to/model.conf', adapter)

sub = "alice"  # the user that wants to access a resource.
obj = "data1"  # the resource that is going to be accessed.
act = "read"  # the operation that the user performs on the resource.

if e.enforce(sub, obj, act)
    # permit alice to read data1casbin_sqlalchemy_adapter
else
    # deny the request, show an error
end
```


### Getting Help

- [Ruby Casbin](https://github.com/CasbinRuby/casbin-ruby)
