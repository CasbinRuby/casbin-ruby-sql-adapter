# frozen_string_literal: true

require 'sequel'
require 'casbin-ruby'

module CasbinRubySqlAdapter
  # the interface for Casbin adapters
  class Adapter < Casbin::Persist::Adapter
    attr_reader :db, :table_name, :filtered

    def initialize(db_url:, db_options: {}, table_name: :casbin_rule, filtered: false)
      @table_name = table_name.to_sym
      @filtered = filtered
      @db = Sequel.connect(db_url, db_options)
      migrate
    end

    # loads all policy rules from the storage.
    def load_policy(model)
      db[table_name].each { |line| load_policy_line(line, model) }
    end

    # returns true if the loaded policy has been filtered.
    def filtered?
      filtered
    end

    # loads all policy rules from the storage.
    def load_filtered_policy(model, filter)
      db[table_name].where(filter).order(:id).each { |line| load_policy_line(line, model) }
      @filtered = true
    end

    # saves all policy rules to the storage.
    def save_policy(model)
      db[table_name].delete
      %w[p g].each { |sec| save_policy_line(model.model[sec]) if model.model.keys.include?(sec) }
    end

    # adds a policy rule to the storage.
    def add_policy(_sec, ptype, rule)
      db[table_name].insert(policy_line(ptype, rule))
    end

    def add_policies(_sec, ptype, rules)
      list = rules.map { |rule| policy_line(ptype, rule) }
      db[table_name].multi_insert(list)
    end

    # removes a policy rule from the storage.
    def remove_policy(_sec, ptype, rule)
      db[table_name].where(policy_line(ptype, rule)).delete
    end

    # removes policy rules that match the filter from the storage.
    # This is part of the Auto-Save feature.
    def remove_filtered_policy(_sec, ptype, field_index, *field_values)
      return false unless field_index >= 0 && field_index <= 5

      index = field_index + field_values.size
      return false unless index >= 1 && index <= 6

      line = { ptype: ptype }
      field_values.each_with_index { |value, i| line["v#{field_index + i}".to_sym] = value }
      db[table_name].where(line).delete == 1
    end

    private

    # TODO: move to generator
    def migrate
      db.create_table? table_name do
        primary_key :id
        String :ptype
        String :v0
        String :v1
        String :v2
        String :v3
        String :v4
        String :v5
      end
    end

    def load_policy_line(line, model)
      arr = [line[:ptype]]
      [line[:v0], line[:v1], line[:v2], line[:v3], line[:v4], line[:v5]].each { |v| arr << v if !v.nil? && !v.empty? }
      super(arr.join(', '), model)
    end

    def save_policy_line(items)
      db.transaction do
        items.each do |ptype, ast|
          ast.policy.each { |rule| db[table_name].insert(policy_line(ptype, rule)) }
        end
      end
    end

    def policy_line(ptype, rule)
      line = { ptype: ptype }
      line.tap { rule.each_with_index { |value, index| line["v#{index}".to_sym] = value } }
    end
  end
end
