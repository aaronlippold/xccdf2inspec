#!/usr/local/bin/ruby
# encoding: utf-8
# author: Matthew Dromazos

require 'happymapper'
require 'nokogiri'

class References
  include HappyMapper
  tag 'references'
  
  attribute :creator, String, tag: 'creator'
  attribute :title, String, tag: 'title'
  attribute :version, String, tag: 'version'
  attribute :location, String, tag: 'location'
  attribute :index, String, tag: 'index'
end

class CCI_Item
  include HappyMapper
  tag 'cci_item'
  
  attribute :id, String, tag: 'id'
  element :status, String, tag: 'status'
  element :publishdate, String, tag: 'publishdate'
  element :contributor, String, tag: 'contributor'
  element :definition, String, tag: 'definition'
  element :type, String, tag: 'type'
  has_many :references, References, tag: 'references'
end

class CCI_Items
  include HappyMapper
  tag 'cci_items'
  
  has_many :cci_item, CCI_Item, tag: 'cci_item'
end

class Metadata
  include HappyMapper
  tag 'metadata'
  
  element :version, String, tag: 'version'
  element :publishdate, String, tag: 'publishdate'
end

class CCI_List
  include HappyMapper
  tag 'cci_list'
  
  attribute :xsi, String, :tag => 'xsi', :namespace => 'xmlns'
  attribute :schemaLocation, String, :tag => 'schemaLocation', :namespace => 'xmlns' 
  has_one :metadata, Metadata, :tag => 'metadata'
  has_many :cci_items, CCI_Items, :tag => 'cci_items'
end