require 'fluent/plugin/filter'
require 'net/http'
require 'json'

module Fluent
  module Plugin
    class KratosEnrichFilter < Filter
      UUID_REGEX = /\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z/.freeze

      Fluent::Plugin.register_filter('kratos_enrich', self)

      helpers :compat_parameters

      config_param :kratos_admin_url, :string, default: ENV.fetch('KRATOS_ADMIN_URL', 'http://kratos:4434')
      config_param :cache_ttl_seconds, :integer, default: 60

      def configure(conf)
        compat_parameters_convert(conf, :parser)
        super
        @traits_cache = {}
      end

      def filter(_tag, _time, record)
        identity_id = find_identity_id(record)
        return record if identity_id.nil?

        enriched = record.dup
        enriched['kratos_identity_id'] = identity_id
        enriched['kratos_traits'] = lookup_traits(identity_id)
        enriched
      rescue StandardError
        record
      end

      private

      def uuid_like?(value)
        value.is_a?(String) && UUID_REGEX.match?(value)
      end

      # Expected input shape is Fluent OpenTelemetry plugin records:
      # record['message'] = JSON string containing OTLP traces payload.
      def find_identity_id(record)
        message = record['message']
        return nil unless message.is_a?(String)

        payload = JSON.parse(message)
        resource_spans = payload['resourceSpans']
        return nil unless resource_spans.is_a?(Array)

        resource_spans.each do |resource_span|
          scope_spans = resource_span['scopeSpans']
          next unless scope_spans.is_a?(Array)

          scope_spans.each do |scope_span|
            spans = scope_span['spans']
            next unless spans.is_a?(Array)

            spans.each do |span|
              events = span['events']
              next unless events.is_a?(Array)

              events.each do |event|
                attrs = event['attributes']
                identity_id = otlp_attr_string_value(attrs, 'IdentityID')
                return identity_id if uuid_like?(identity_id)
              end
            end
          end
        end

        nil
      rescue JSON::ParserError
        nil
      end

      def otlp_attr_string_value(attrs, key)
        return nil unless attrs.is_a?(Array)

        attrs.each do |attr|
          next unless attr.is_a?(Hash)
          next unless attr['key'] == key

          value = attr['value']
          next unless value.is_a?(Hash)

          str = value['stringValue']
          return str if str.is_a?(String)
        end

        nil
      end

      def lookup_traits(identity_id)
        now = Time.now.to_i
        cached = @traits_cache[identity_id]
        return cached[:traits] if cached && cached[:expires_at] > now

        uri = URI(@kratos_admin_url + '/admin/identities/' + identity_id)
        res = Net::HTTP.get_response(uri)
        traits = nil

        if res.is_a?(Net::HTTPSuccess)
          parsed = JSON.parse(res.body) rescue {}
          traits = parsed['traits']
        end

        @traits_cache[identity_id] = {
          traits: traits,
          expires_at: now + @cache_ttl_seconds,
        }

        traits
      end
    end
  end
end
