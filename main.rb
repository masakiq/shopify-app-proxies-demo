# frozen_string_literal: true

require 'openssl'
require 'sinatra'
require 'httparty'
require 'jwt'
require 'rack/utils'
require 'pry'

class InvalidProxyRequest < StandardError; end

set :protection, except: :frame_options

not_found do
  response.headers['Content-Type'] = 'application/liquid'
  'not found'
end

get '/' do
  puts request.body.rewind

  shop = params['shop']
  client_id = ENV['SHOPIFY_APP_API_KEY']
  redirect_uri = URI.encode_www_form_component("#{ENV['SHOPIFY_APP_BASE_URL']}/callback")

  uri = "https://#{shop}/admin/oauth/authorize?"\
        "client_id=#{client_id}&"\
        'scope=read_customers,write_customers&'\
        "redirect_uri=#{redirect_uri}&"\
        'state=hogehoge'
  puts uri

  redirect uri
end

get '/callback' do
  # skip verification
  puts request.body.rewind
  code = params['code']
  shop = params['shop']

  url = "https://#{shop}/admin/oauth/access_token"
  payload = {
    code: code,
    client_id: ENV['SHOPIFY_APP_API_KEY'],
    client_secret: ENV['SHOPIFY_APP_API_SECRET_KEY']
  }

  res = HTTParty.post(url, body: payload)

  puts '*' * 30
  puts res
  puts '*' * 30
end

get '/proxy/' do
  begin
    verify_proxy_signature(request.query_string)
  rescue InvalidProxyRequest
    response.headers['Content-Type'] = 'application/liquid'
    return 'Invalid Proxy Request'
  end

  puts '***** REQUEST PARAMS *****'
  params.each do |key, val|
    puts "#{key}: #{val}"
  end
  puts '***** REQUEST HEADERS *****'
  env.each do |key, val|
    puts "#{key}: #{val}"
  end
  puts '***** HTTP HEADERS *****'
  headers = request.env.select { |k, _v| k.start_with?('HTTP_') }
  headers.each do |k, v|
    puts "#{k} -> #{v}"
  end
  puts '*' * 20
end

get '/proxy/customer_token' do
  begin
    verify_proxy_signature(request.query_string)
  rescue InvalidProxyRequest
    response.status = 400
    json = <<~JSON
      {"message":"invalid request"}
    JSON
    return json
  end

  jwt = encode_jwt(params['customer_id'], params['shop'])

  response.headers['Content-Type'] = 'application/liquid'
  <<~LIQ
    {% layout none %}
    {% if customer.id == nil or customer.id != #{params['customer_id']} %}
      {"status":401,"message":"unauthorized","data":null}
    {% else %}
      {"status":200,"message":"success","data":{"token":"#{jwt}"}}
    {% endif %}
  LIQ
end

get '/proxy/customer_info' do
  response.headers['Content-Type'] = 'application/json'
  begin
    verify_proxy_signature(request.query_string)
  rescue InvalidProxyRequest
    response.status = 400
    json = <<~JSON
      {"message":"invalid request"}
    JSON
    return json
  end

  begin
    customer_token = decode_jwt(params['customer_token'])
    customer_id = customer_token['sub']
    <<~JSON
      {"message":"success","data":{"customer_id":"#{customer_id}"}}
    JSON
  rescue StandardError => e
    puts e
    response.status = 404
    <<~JSON
      {"message":"fail","data":{"customer_id":"#{e.message}"}}
    JSON
  end
end

get '/proxy/account' do
  response.headers['Content-Type'] = 'application/liquid'
  begin
    verify_proxy_signature(request.query_string)
  rescue InvalidProxyRequest
    return 'Invalid Proxy Request'
  end

  <<~HTML
    <body>
      </br>
      </br>
      </br>
      {% if customer.id == nil %}
        ???????????????????????????
      {% else %}
        ???????????????(customerId: {{ customer.id }})
      {% endif %}
      </br>
      <label>Customer ID</label>
      <input type="text" id="customerId" name="customerId" value="{{ customer.id }}">
      <input type="button" id="clearCustomerId" value="Clear">
      <input type="button" id="getCustomerToken" value="Get Customer Token">
      </br>
      <label>Customer Token</label>
      <input type="text" id="customerToken" name="customerToken" value="">
      <input type="button" id="clearCustomerToken" value="Clear">
      <input type="button" id="getCustomerInfo" value="Get Customer Info">
      </br>
      <label>Customer Info</label>
      <input type="text" id="customerInfo" name="customerInfo" value="">
      <input type="button" id="clearCustomerInfo" value="Clear">
      </br>
      </br>
      <a href="{{ routes.account_logout_url }}">???????????????</a>
    </body>
    <script type="text/javascript">
      async function getCustomerToken() {
        const customerId = document.getElementById('customerId').value;
        const url = '/apps/proxy/customer_token?customer_id=' + customerId;
        const result = await fetch(
          url,
          {
            headers: {
              accept: "application/json, text/plain, */*"
            },
            credentials: 'include'
          }
        );
        const json = await result.json();
        if (json.status === 200) {
          const token = json.data.token;
          document.getElementById('customerToken').value = token;
        } else {
          document.getElementById('customerToken').value = 'no data';
        }
      }
      document.getElementById('getCustomerToken').addEventListener('click', getCustomerToken);

      async function getCustomerInfo() {
        const customerToken = document.getElementById('customerToken').value;
        const url = '/apps/proxy/customer_info?customer_token=' + customerToken;
        const result = await fetch(
          url,
          {
            headers: {
              accept: "application/json, text/plain, */*"
            },
            credentials: 'include'
          }
        );
        const json = await result.json();
        const customerId = json.data.customer_id;
        document.getElementById('customerInfo').value = customerId;
      }
      document.getElementById('getCustomerInfo').addEventListener('click', getCustomerInfo);

      function clearCustomerId() {
        document.getElementById('customerId').value = '';
      }
      document.getElementById('clearCustomerId').addEventListener('click', clearCustomerId);

      function clearCustomerToken() {
        document.getElementById('customerToken').value = '';
      }
      document.getElementById('clearCustomerToken').addEventListener('click', clearCustomerToken);

      function clearCustomerInfo() {
        document.getElementById('customerInfo').value = '';
      }
      document.getElementById('clearCustomerInfo').addEventListener('click', clearCustomerInfo);
    </script>
  HTML
end

get '/proxy/secure_account' do
  begin
    verify_proxy_signature(request.query_string)
  rescue InvalidProxyRequest
    return 'Invalid Proxy Request'
  end

  response.headers['Content-Type'] = 'application/liquid'
  <<~HTML
    <body>
      <input type="hidden" id="customerId" name="customerId" value="{{ customer.id }}">
      <iframe
        id="customerContext"
        title="Customer Context"
        width="100%"
        height="500px"
        src="#{ENV['SHOPIFY_APP_BASE_URL']}/original/secure_account">
      </iframe>
    </body>
    <script type="text/javascript">
      async function getCustomerToken() {
        const customerId = document.getElementById('customerId').value;
        const url = '/apps/proxy/customer_token?customer_id=' + customerId;
        const result = await fetch(
          url,
          {
            headers: {
              accept: "application/json, text/plain, */*"
            },
            credentials: 'include'
          }
        );
        const json = await result.json();
        if (json.status === 200) {
          const customerToken = json.data.token;
          let customerContext = document.getElementById('customerContext').contentWindow;
          customerContext.postMessage(customerToken, '#{ENV['SHOPIFY_APP_BASE_URL']}');

          // Invalid Access!! Blocked by CORS policy.
          // getCustomerInfo(customerToken);
        } else {
          console.log('error');
        }
      }

      async function getCustomerInfo(customerToken) {
        const url = '#{ENV['SHOPIFY_APP_BASE_URL']}/original/secure_customer_info?customer_token=' + customerToken;
        const result = await fetch(
          url,
          {
            headers: {
              accept: "application/json, text/plain, */*"
            },
            credentials: 'include'
          }
        );
        const json = await result.json();
        const customerId = json.data.customer_id;
        console.log(customerId);
      }

      window.onload = getCustomerToken();

      // window.addEventListener('message', function(event) {
      //   console.log(event.data);
      // }, false);
    </script>
  HTML
end

get '/original/secure_account' do
  # headers = request.env.select { |k, _v| k.start_with?('HTTP_') }
  # headers.each do |k, v|
  #   puts "#{k} -> #{v}"
  # end
  response.headers['Content-Type'] = 'text/html'
  <<~HTML
    <body>
      </br>
      </br>
      </br>
      <label>Customer Info</label>
      <input type="text" id="customerInfo" name="customerInfo" value="">
    </body>
    <script type="text/javascript">
      async function getCustomerInfo(customerToken) {
        const url = '#{ENV['SHOPIFY_APP_BASE_URL']}/original/secure_customer_info?customer_token=' + customerToken;
        const result = await fetch(
          url,
          {
            headers: {
              accept: "application/json, text/plain, */*"
            },
            credentials: 'include'
          }
        );
        const json = await result.json();
        const customerId = json.data.customer_id;
        document.getElementById('customerInfo').value = customerId;
      }

      window.addEventListener('message', function(event) {
        getCustomerInfo(event.data);
        // event.source.postMessage(customerId, event.origin);
      }, false);
    </script>
  HTML
end

get '/original/secure_customer_info' do
  response.headers['Content-Type'] = 'application/json'
  begin
    customer_token = decode_jwt(params['customer_token'])
    customer_id = customer_token['sub']
    <<~JSON
      {"message":"success","data":{"customer_id":"#{customer_id}"}}
    JSON
  rescue StandardError => e
    puts e
    response.status = 404
    <<~JSON
      {"message":"fail","data":{"customer_id":"#{e.message}"}}
    JSON
  end
end

def verify_proxy_signature(query_string)
  puts query_string

  query_hash = Rack::Utils.parse_query(query_string)
  signature = query_hash.delete('signature')
  sorted_params = query_hash.collect { |k, v| "#{k}=#{Array(v).join(',')}" }.sort.join
  calculated_signature = OpenSSL::HMAC.hexdigest(
    OpenSSL::Digest.new('sha256'),
    ENV['SHOPIFY_APP_API_SECRET_KEY'],
    sorted_params
  )
  raise InvalidProxyRequest unless signature == calculated_signature
end

def encode_jwt(customer_id, shop)
  current_time = Time.now.to_i

  payload = {
    sub: customer_id,
    iat: current_time,
    exp: current_time + 10,
    iss: shop,
    typ: 'customer_token'
  }

  JWT.encode payload, hmac_secret_key, 'HS512', { type: 'JWT' }
end

def decode_jwt(token)
  JWT.decode(token, hmac_secret_key, true, { algorithm: 'HS512' })&.first
end

def hmac_secret_key
  ENV['SHOPIFY_APP_HMAC_SECRET_KEY']
end
