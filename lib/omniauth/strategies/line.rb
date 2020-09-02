require "omniauth-oauth2"
require "json"

module OmniAuth
  module Strategies
    class Line < OmniAuth::Strategies::OAuth2
      class NoAuthorizationCodeError < StandardError; end

      option :name, "line"
      option :scope, "profile openid email"

      option :client_options, {
        site: "https://access.line.me",
        authorize_url: "/oauth2/v2.1/authorize",
        token_url: "/oauth2/v2.1/token",
      }

      option :authorization_code_from_signed_request_in_cookie, nil
      
      option :access_token_options, {
        grant_type: "authorization_code",
      }

      def callback_url
        if options.authorization_code_from_signed_request_in_cookie
          ""
        else
          # Fixes regression in omniauth-oauth2 v1.4.0 by https://github.com/intridea/omniauth-oauth2/commit/85fdbe117c2a4400d001a6368cc359d88f40abc7
          options[:callback_url] || (full_host + script_name + callback_path)
        end
      end

      # host changed
      def callback_phase
        options[:client_options][:site] = "https://api.line.me"
        with_authorization_code! do
          super
        end
      rescue NoAuthorizationCodeError => e
        fail!(:no_authorization_code, e)
      end

      uid { raw_info["userId"] }

      info do
        {
          name: raw_info["displayName"],
          image: raw_info["pictureUrl"],
          description: raw_info["statusMessage"],
          email: email_from_id_token,
        }
      end

      def access_token_options
        options.access_token_options.inject({}) { |h, (k, v)| h[k.to_sym] = v; h }
      end

      def build_access_token
        super.tap do |token|
          token.options.merge!(access_token_options)
        end
      end

      def email_from_id_token
        if !options[:skip_jwt] && !access_token["id_token"].nil?
          decoded = ::JWT.decode(access_token["id_token"], nil, false).first
          payload_decoded = base64url_decode(access_token["id_token"].split(".")[1])
          #Rails.logger.info  "JWT decode payload =>" + payload_decoded.to_s
          email = payload_decoded["email"]
          # We have to manually verify the claims because the third parameter to
          # JWT.decode is false since no verification key is provided.
          ::JWT::Verify.verify_claims(decoded,
                                      verify_iss: true,
                                      iss: "https://access.line.me",
                                      verify_aud: true,
                                      aud: options.client_id,
                                      verify_sub: false,
                                      #     verify_expiration: true,
                                      verify_not_before: true,
                                      verify_iat: true,
                                      verify_jti: false,
                                      leeway: options[:jwt_leeway])
        end
        return email
      end

      def base64url_decode(target)
        rem = (target.length) % 4
        if (rem > 0)
          target += "=" * (4 - rem)
        end
        return JSON.load(Base64.urlsafe_decode64(target))
      end

      # Picks the authorization code in order, from:
      #
      # 1. The request 'code' param (manual callback from standard server-side flow)
      # 2. A signed request from cookie (passed from the client during the client-side flow)
      def with_authorization_code!
        if request.params.key?("code")
          yield
        elsif code_from_signed_request = signed_request_from_cookie && signed_request_from_cookie["code"]
          request.params["code"] = code_from_signed_request
          options.authorization_code_from_signed_request_in_cookie = true
          
          original_provider_ignores_state = options.provider_ignores_state
          options.provider_ignores_state = true
          begin
            yield
          ensure
            request.params.delete("code")
            options.authorization_code_from_signed_request_in_cookie = false
            options.provider_ignores_state = original_provider_ignores_state
          end
        else
          raise NoAuthorizationCodeError, "must pass either a `code`"
        end
      end

      def prune!(hash)
        hash.delete_if do |_, v|
          prune!(v) if v.is_a?(Hash)
          v.nil? || (v.respond_to?(:empty?) && v.empty?)
        end
      end

      # Require: Access token with PROFILE permission issued.
      def raw_info
        @raw_info ||= JSON.load(access_token.get("v2/profile").body)
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end
    end
  end
end
