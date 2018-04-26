#!/usr/local/bin/ruby
# encoding: utf-8
# author: Aaron Lippold
# author: Rony Xavier rx294@nyu.edu
# author: Matthew Dromazos

require 'happymapper'
require 'nokogiri'

class Check
  include HappyMapper
  tag 'check'
  
  element 'check-content', String, tag: 'check-content'
end

class Fix
  include HappyMapper
  tag 'fix'
  
  attribute :id, String, tag: 'id'
end

class Description
  include HappyMapper
  tag 'description'
  
  #content :raw_details, String
  content :details, "DescriptionDetails"
  
  detail_tags = [:vuln_discussion, :false_positives, :false_negatives, :documentable, 
    :mitigations, :severity_override_guidance, :potential_impacts, 
    :third_party_tools, :mitigation_controls, :responsibility, :ia_controls]
    
  detail_tags.each do |name|
    define_method name do
      details.send(name)
    end
  end
end

class DescriptionDetails
  include HappyMapper
  tag 'Details'
  
  element :vuln_discussion, String, tag: 'VulnDiscussion'
  element :false_positives, String, tag: 'FalsePositives'
  element :false_negatives, String, tag: 'FalseNegatives'
  element :documentable, Boolean, tag: 'Documentable'
  element :mitigations, String, tag: 'Mitigations'
  element :severity_override_guidance, String, tag: 'SeverityOverrideGuidance'
  element :potential_impacts, String, tag: 'PotentialImpacts'
  element :third_party_tools, String, tag: 'ThirdPartyTools'
  element :mitigation_controls, String, tag: 'MitigationControl'
  element :responsibility, String, tag: 'Responsibility'
  element :ia_controls, String, tag: 'IAControls'
end

class Rule
  include HappyMapper
  tag 'Rule'
  
  attribute :id, String, tag: 'id'
  attribute :severity, String, tag: 'severity'
  element :version, String, tag: 'version'
  element :title, String, tag: 'title'
  has_one :description, Description, tag: 'description'
  has_many :idents, String, tag: 'ident'
  element :fixtext, String, tag: 'fixtext'
  has_one :fix, Fix, tag: 'fix'
  has_one :check, Check, tag: 'check'

end

class Group
  include HappyMapper
  tag 'Group'
  
  attribute :id, String, tag: 'id'
  element :title, String, tag: 'title'
  element :description, String, tag: 'description'
  has_one :rule, Rule, tag: 'Rule'
end

class ReferenceInfo
  include HappyMapper
  tag 'reference'
  
  attribute :href, String, :tag => 'href'
  element :publisher, String, :tag => 'publisher', :namespace => 'dc'
  element :source, String, :tag => 'source', :namespace => 'dc'
end

class ReleaseDate
  include HappyMapper
  tag 'status'
  
  attribute :release_date, String, tag: 'date'
end

class Benchmark
  include HappyMapper
  tag 'Benchmark'
  
  has_one :release_date, ReleaseDate, tag: 'status'
  element :status, String, tag: 'status'
  element :title, String, tag: 'title'
  element :description, String, tag: 'description'
  element :version, String, tag: 'version'
  has_one :reference, ReferenceInfo, tag: 'reference'
  has_many :group, Group, tag: 'Group'
end

class DescriptionDetailsType
  def self.apply?(value, convert_to_type)
    value.kind_of?(String)
  end

  def self.apply(value)
    DescriptionDetails.parse "<Details>#{value}</Details>"
  end

  def self.type
    DescriptionDetails
  end
end
HappyMapper::SupportedTypes.register DescriptionDetailsType