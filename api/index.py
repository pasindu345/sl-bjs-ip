import os
import logging
from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import ipaddress
import requests
from functools import lru_cache
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev_secret_key")

# Configure rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour", "20 per minute"],
    storage_uri="memory://",
)

# Configuration
IPGEOLOCATION_API_KEY = os.getenv("IPGEOLOCATION_API_KEY", "e253db1e509c42de99061aa8c23b803d")
BASE_URL = "https://api.ipgeolocation.io/ipgeo"

class IPValidationError(Exception):
    pass

@lru_cache(maxsize=1024)
def get_ip_details(ip_address):
    """Get complete IP details from ipgeolocation.io"""
    if not is_valid_ip(ip_address):
        raise IPValidationError("Invalid IP address format")
        
    params = {
        "apiKey": IPGEOLOCATION_API_KEY,
        "ip": ip_address,
        "fields": "ip,hostname,continent_code,continent_name,country_code2,country_code3,country_name,country_name_official,country_capital,state_prov,state_code,district,city,zipcode,latitude,longitude,is_eu,calling_code,country_tld,languages,country_flag,geoname_id,isp,connection_type,organization,country_emoji,asn,currency,time_zone,security,user_agent",
        "excludes": ""
    }
    
    try:
        response = requests.get(BASE_URL, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"API request failed: {str(e)}")
        raise Exception("Failed to fetch IP details from provider")

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def format_response(data, status="success", message=None):
    """Standard response format"""
    return {
        "status": status,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "developer": {
            "name": "Pasindu 🇱🇰",
            "contact": "Telegram @sl_bjs",
            "message": message or "Join our Telegram channel: https://t.me/sl_bjs"
        },
        "data" if status == "success" else "error": data
    }

@app.route('/')
def index():
    return jsonify(format_response(
        data={
            "endpoints": {
                "lookup": "/api/lookup?ip=<IP_ADDRESS>",
                "validate": "/api/validate?ip=<IP_ADDRESS>",
                "set_api_key": "/api/set-ipgeolocation-key (POST)"
            }
        },
        message="Welcome to Advanced IP API Service"
    ))

@app.route('/api/lookup', methods=['GET'])
@limiter.limit("60 per minute")
def lookup_ip():
    ip_address = request.args.get('ip', request.remote_addr)
    try:
        ip_details = get_ip_details(ip_address)
        logger.debug(f"IP details fetched for {ip_address}")
        return jsonify(format_response(
            data=ip_details,
            message="Advanced IP data retrieved successfully"
        ))
    except IPValidationError as e:
        logger.warning(f"IP validation error: {str(e)}")
        return jsonify(format_response(
            data={"details": str(e)},
            status="error",
            message="Invalid IP address provided"
        )), 400
    except Exception as e:
        logger.error(f"Error getting IP details: {str(e)}")
        return jsonify(format_response(
            data={"details": "Service unavailable"},
            status="error",
            message="Failed to fetch IP details"
        )), 500

@app.route('/api/validate', methods=['GET'])
@limiter.limit("100 per minute")
def validate_ip():
    ip_address = request.args.get('ip')
    if not ip_address:
        return jsonify(format_response(
            data={"details": "Missing IP parameter"},
            status="error",
            message="No IP address provided"
        )), 400
        
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        return jsonify(format_response(
            data={
                "valid": True,
                "type": "IPv6" if ip_obj.version == 6 else "IPv4",
                "is_private": ip_obj.is_private,
                "is_global": ip_obj.is_global,
                "is_multicast": ip_obj.is_multicast,
                "is_loopback": ip_obj.is_loopback
            },
            message="IP validation successful"
        ))
    except ValueError:
        return jsonify(format_response(
            data={"details": f"'{ip_address}' is invalid"},
            status="error",
            message="Invalid IP address format"
        )), 400

@app.route('/api/set-ipgeolocation-key', methods=['POST'])
@limiter.limit("1 per hour")
def set_ipgeolocation_key():
    try:
        api_key = request.json.get('api_key')
        if not api_key:
            return jsonify(format_response(
                data={"details": "Empty API key"},
                status="error",
                message="No API key provided"
            )), 400
            
        global IPGEOLOCATION_API_KEY
        IPGEOLOCATION_API_KEY = api_key
        get_ip_details.cache_clear()
        
        return jsonify(format_response(
            data={},
            message="API key updated successfully"
        ))
    except Exception as e:
        logger.error(f"Error setting API key: {str(e)}")
        return jsonify(format_response(
            data={"details": "Internal server error"},
            status="error",
            message="Failed to update API key"
        )), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify(format_response(
        data={"details": "Too many requests"},
        status="error",
        message="Rate limit exceeded. Please try again later."
    )), 429

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
