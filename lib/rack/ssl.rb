require 'rack'
require 'rack/request'

module Rack
  class SSL

    def initialize(app, options = {})
      @app = app
    end

    def call(env)
      @request = Request.new(env)
      if ssl_request?
        status, headers, body = @app.call(env)
        # headers = hsts_headers.merge(headers)
        flag_cookies_as_secure!(headers)
        [status, headers, body]
      else
        status, headers, body = @app.call(env)
        [status, headers, body]
      end
    end

    private

      def ssl_request?
        current_scheme == 'https'
      end

      def current_scheme
        if @request.env['HTTPS'] == 'on' || @request.env['HTTP_X_SSL_REQUEST'] == 'on'
          'https'
        elsif @request.env['HTTP_X_FORWARDED_PROTO']
          @request.env['HTTP_X_FORWARDED_PROTO'].split(',')[0]
        else
          @request.scheme
        end
      end

      def flag_cookies_as_secure!(headers)
        if cookies = headers['Set-Cookie']
          # Rack 1.1's set_cookie_header! will sometimes wrap
          # Set-Cookie in an array
          unless cookies.respond_to?(:to_ary)
            cookies = cookies.split("\n")
          end

          headers['Set-Cookie'] = cookies.map { |cookie|
            if cookie !~ /; secure(;|$)/
              "#{cookie}; secure"
            else
              cookie
            end
          }.join("\n")
        end
      end
  end
end