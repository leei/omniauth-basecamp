require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    class Basecamp < OmniAuth::Strategies::OAuth2
      option :client_options,
             :site => 'https://launchpad.37signals.com',
             :authorize_url => '/authorization/new',
             :token_url => '/authorization/token'

      uid do
        identity['id']
      end

      info do
        {
          name: "#{identity['first_name']} #{identity['last_name']}",
          email: identity['email_address']
        }
      end

      def authorize_params
        super.tap do |params|
          params[:response_type] = 'code'
          params[:client_id] = client.id
          params[:redirect_uri] ||= callback_url
          params[:type] = 'web_server'
        end
      end

      def request_phase
        super
      end

      def build_access_token
        token_params = {
          :code => request.params['code'],
          :redirect_uri => callback_url,
          :client_id => client.id,
          :client_secret => client.secret,
          :type => 'web_server'
        }
        client.get_token(token_params)
      end

      protected

      def raw_info
        @raw_info ||= access_token.get('/authorization.json').parsed
      end

      def identity
        raw_info
        raw_info['identity']
      end
    end
  end
end
