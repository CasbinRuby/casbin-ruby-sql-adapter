# frozen_string_literal: true

require 'sqlite3'
require 'casbin-ruby'
require 'casbin-ruby-sql-adapter/adapter'

describe CasbinRubySqlAdapter::Adapter do
  let(:db_url) { "sqlite://#{@db}" }
  let(:path) { File.expand_path('rbac_model.conf', __dir__) }
  let(:adapter) { described_class.new(db_url: db_url) }
  let(:enf) { Casbin::Enforcer.new(path, adapter) }

  before do
    @db = 'test.db'
    table_name = :casbin_rule
    SQLite3::Database.new @db
    db = described_class.new(db_url: "sqlite://#{@db}", table_name: table_name).db
    db[table_name].insert(ptype: 'p', v0: 'alice', v1: 'data1', v2: 'read')
    db[table_name].insert(ptype: 'p', v0: 'bob', v1: 'data2', v2: 'write')
    db[table_name].insert(ptype: 'p', v0: 'data2_admin', v1: 'data2', v2: 'read')
    db[table_name].insert(ptype: 'p', v0: 'data2_admin', v1: 'data2', v2: 'write')
    db[table_name].insert(ptype: 'g', v0: 'alice', v1: 'data2_admin')
  end

  after do
    Sequel.connect("sqlite://#{@db}").drop_table?(:casbin_rule)
  end

  it 'enforcer_basic' do
    expect(enf.enforce('alice', 'data1', 'read')).to be_truthy
    expect(enf.enforce('bob', 'data1', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'write')).to be_truthy
    expect(enf.enforce('alice', 'data2', 'read')).to be_truthy
    expect(enf.enforce('alice', 'data2', 'write')).to be_truthy
    expect(enf.enforce('bogus', 'data2', 'write')).to be_falsey
  end

  it '#add_permission_for_user' do
    expect(enf.enforce('eve', 'data3', 'read')).to be_falsey
    enf.add_permission_for_user('eve', 'data3', 'read')
    expect(enf.enforce('eve', 'data3', 'read')).to be_truthy
  end

  it '#add_policy' do
    expect(enf.enforce('eve', 'data3', 'read')).to be_falsey
    enf.add_policy(%w[eve data3 read])
    expect(enf.enforce('eve', 'data3', 'read')).to be_truthy
  end

  it '#add_policies' do
    expect(enf.enforce('eve', 'data3', 'read')).to be_falsey
    enf.add_policies([%w[eve data3 read], %w[eve data4 read]])
    expect(enf.enforce('eve', 'data3', 'read')).to be_truthy
    expect(enf.enforce('eve', 'data4', 'read')).to be_truthy
  end

  it '#save_policy' do
    expect(enf.enforce('alice', 'data4', 'read')).to be_falsey
    model = enf.model
    model.clear_policy
    model.add_policy('p', 'p', %w[alice data4 read])

    adapter = enf.adapter
    adapter.save_policy(model)

    expect(enf.enforce('alice', 'data4', 'read')).to be_truthy
  end

  it '#remove_policy' do
    expect(enf.enforce('alice', 'data5', 'read')).to be_falsey
    enf.add_permission_for_user('alice', 'data5', 'read')
    expect(enf.enforce('alice', 'data5', 'read')).to be_truthy
    enf.delete_permission_for_user('alice', 'data5', 'read')
    expect(enf.enforce('alice', 'data5', 'read')).to be_falsey
  end

  it '#remove_policies' do
    expect(enf.enforce('alice', 'data5', 'read')).to be_falsey
    expect(enf.enforce('alice', 'data6', 'read')).to be_falsey
    enf.add_policies([%w[alice data5 read], %w[alice data6 read]])
    expect(enf.enforce('alice', 'data5', 'read')).to be_truthy
    expect(enf.enforce('alice', 'data6', 'read')).to be_truthy
    enf.remove_policies([%w[alice data5 read], %w[alice data6 read]])
    expect(enf.enforce('alice', 'data5', 'read')).to be_falsey
    expect(enf.enforce('alice', 'data6', 'read')).to be_falsey
  end

  it '#remove_filtered_policy' do
    expect(enf.enforce('alice', 'data1', 'read')).to be_truthy
    enf.remove_filtered_policy(1, 'data1')
    expect(enf.enforce('alice', 'data1', 'read')).to be_falsey

    expect(enf.enforce('bob', 'data2', 'write')).to be_truthy
    expect(enf.enforce('alice', 'data2', 'read')).to be_truthy
    expect(enf.enforce('alice', 'data2', 'write')).to be_truthy

    enf.remove_filtered_policy(1, 'data2', 'read')

    expect(enf.enforce('bob', 'data2', 'write')).to be_truthy
    expect(enf.enforce('alice', 'data2', 'read')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'write')).to be_truthy

    enf.remove_filtered_policy(2, 'write')

    expect(enf.enforce('bob', 'data2', 'write')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'write')).to be_falsey
  end

  it '#filtered_policy' do
    enf.load_filtered_policy(ptype: 'p')
    expect(enf.enforce('alice', 'data1', 'read')).to be_truthy
    expect(enf.enforce('alice', 'data1', 'write')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'read')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'write')).to be_truthy

    enf.load_filtered_policy(v0: 'alice')
    expect(enf.enforce('alice', 'data1', 'read')).to be_truthy
    expect(enf.enforce('alice', 'data1', 'write')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'read')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'write')).to be_falsey
    expect(enf.enforce('data2_admin', 'data2', 'read')).to be_falsey
    expect(enf.enforce('data2_admin', 'data2', 'write')).to be_falsey

    enf.load_filtered_policy(v0: 'bob')
    expect(enf.enforce('alice', 'data1', 'read')).to be_falsey
    expect(enf.enforce('alice', 'data1', 'write')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'read')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'write')).to be_truthy
    expect(enf.enforce('data2_admin', 'data2', 'read')).to be_falsey
    expect(enf.enforce('data2_admin', 'data2', 'write')).to be_falsey

    enf.load_filtered_policy(v0: 'data2_admin')
    expect(enf.enforce('data2_admin', 'data2', 'read')).to be_truthy
    expect(enf.enforce('data2_admin', 'data2', 'read')).to be_truthy
    expect(enf.enforce('alice', 'data1', 'read')).to be_falsey
    expect(enf.enforce('alice', 'data1', 'write')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'read')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'write')).to be_falsey

    enf.load_filtered_policy(v0: %w[alice bob])
    expect(enf.enforce('alice', 'data1', 'read')).to be_truthy
    expect(enf.enforce('alice', 'data1', 'write')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'read')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'write')).to be_truthy
    expect(enf.enforce('data2_admin', 'data2', 'read')).to be_falsey
    expect(enf.enforce('data2_admin', 'data2', 'write')).to be_falsey

    enf.load_filtered_policy(v1: 'data1')
    expect(enf.enforce('alice', 'data1', 'read')).to be_truthy
    expect(enf.enforce('alice', 'data1', 'write')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'read')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'write')).to be_falsey
    expect(enf.enforce('data2_admin', 'data2', 'read')).to be_falsey
    expect(enf.enforce('data2_admin', 'data2', 'write')).to be_falsey

    enf.load_filtered_policy(v1: 'data2')
    expect(enf.enforce('alice', 'data1', 'read')).to be_falsey
    expect(enf.enforce('alice', 'data1', 'write')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'read')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'write')).to be_truthy
    expect(enf.enforce('data2_admin', 'data2', 'read')).to be_truthy
    expect(enf.enforce('data2_admin', 'data2', 'write')).to be_truthy

    enf.load_filtered_policy(v2: 'read')
    expect(enf.enforce('alice', 'data1', 'read')).to be_truthy
    expect(enf.enforce('alice', 'data1', 'write')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'read')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'write')).to be_falsey
    expect(enf.enforce('data2_admin', 'data2', 'read')).to be_truthy
    expect(enf.enforce('data2_admin', 'data2', 'write')).to be_falsey

    enf.load_filtered_policy(v2: 'write')
    expect(enf.enforce('alice', 'data1', 'read')).to be_falsey
    expect(enf.enforce('alice', 'data1', 'write')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'read')).to be_falsey
    expect(enf.enforce('alice', 'data2', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data1', 'write')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'read')).to be_falsey
    expect(enf.enforce('bob', 'data2', 'write')).to be_truthy
    expect(enf.enforce('data2_admin', 'data2', 'read')).to be_falsey
    expect(enf.enforce('data2_admin', 'data2', 'write')).to be_truthy
  end
end
