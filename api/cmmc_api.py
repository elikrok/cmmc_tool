# api/cmmc_api.py
"""RESTful API for CMMC compliance tool with plugin architecture."""

from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional, Any
import uvicorn
import asyncio
from datetime import datetime
import json
import uuid
from pathlib import Path

# Plugin framework
from abc import ABC, abstractmethod
import importlib
import inspect

# Data models
class ComplianceRequest(BaseModel):
    """Request model for compliance checking."""
    device_configs: List[str]
    baseline_configs: List[str] 
    vendor_type: Optional[str] = None
    skip_connectivity: bool = True
    generate_reports: bool = True
    custom_options: Dict[str, Any] = {}

class ComplianceResult(BaseModel):
    """Response model for compliance results."""
    job_id: str
    hostname: str
    vendor_type: str
    vendor_display: str
    detected_version: Optional[str]
    compliant: bool
    compliance_rate: float
    checks: Dict[str, Any]
    timestamp: datetime
    reports_generated: List[str] = []

class JobStatus(BaseModel):
    """Job status model."""
    job_id: str
    status: str  # pending, running, completed, failed
    progress: float
    message: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    results: Optional[List[ComplianceResult]] = None

# Plugin architecture
class BaseIntegrationPlugin(ABC):
    """Base class for integration plugins."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name."""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version."""
        pass
    
    @abstractmethod
    async def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the plugin with configuration."""
        pass
    
    @abstractmethod
    async def send_results(self, results: List[ComplianceResult]) -> bool:
        """Send compliance results to external system."""
        pass
    
    @abstractmethod
    async def fetch_configs(self, device_filters: Dict[str, Any]) -> List[Dict[str, str]]:
        """Fetch device configurations from external system."""
        pass

class NautobotPlugin(BaseIntegrationPlugin):
    """Nautobot integration plugin."""
    
    @property
    def name(self) -> str:
        return "nautobot"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def __init__(self):
        self.base_url = None
        self.api_token = None
        self.session = None
    
    async def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize Nautobot connection."""
        try:
            import aiohttp
            
            self.base_url = config.get('base_url')
            self.api_token = config.get('api_token')
            
            if not self.base_url or not self.api_token:
                return False
            
            self.session = aiohttp.ClientSession(
                headers={'Authorization': f'Token {self.api_token}'}
            )
            
            # Test connection
            async with self.session.get(f"{self.base_url}/api/") as response:
                return response.status == 200
                
        except Exception as e:
            print(f"Nautobot initialization failed: {e}")
            return False
    
    async def send_results(self, results: List[ComplianceResult]) -> bool:
        """Send compliance results to Nautobot custom fields."""
        try:
            for result in results:
                # Update device custom fields with compliance status
                device_data = {
                    'custom_fields': {
                        'cmmc_compliance_status': 'compliant' if result.compliant else 'non_compliant',
                        'cmmc_compliance_rate': result.compliance_rate,
                        'cmmc_last_check': result.timestamp.isoformat(),
                        'cmmc_vendor_type': result.vendor_type
                    }
                }
                
                # Find device by hostname
                search_url = f"{self.base_url}/api/dcim/devices/?name={result.hostname}"
                async with self.session.get(search_url) as response:
                    if response.status == 200:
                        devices = await response.json()
                        if devices['results']:
                            device_id = devices['results'][0]['id']
                            
                            # Update device
                            update_url = f"{self.base_url}/api/dcim/devices/{device_id}/"
                            async with self.session.patch(update_url, json=device_data) as update_response:
                                if update_response.status != 200:
                                    print(f"Failed to update device {result.hostname}")
                                    return False
            
            return True
            
        except Exception as e:
            print(f"Failed to send results to Nautobot: {e}")
            return False
    
    async def fetch_configs(self, device_filters: Dict[str, Any]) -> List[Dict[str, str]]:
        """Fetch device configurations from Nautobot."""
        try:
            configs = []
            
            # Build filter query
            filter_params = []
            if device_filters.get('site'):
                filter_params.append(f"site={device_filters['site']}")
            if device_filters.get('role'):
                filter_params.append(f"device_role={device_filters['role']}")
            
            query_string = "&".join(filter_params)
            url = f"{self.base_url}/api/dcim/devices/"
            if query_string:
                url += f"?{query_string}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    devices = await response.json()
                    
                    for device in devices['results']:
                        # Get config from custom field or config context
                        config_data = device.get('config_context', {}).get('running_config')
                        if config_data:
                            configs.append({
                                'hostname': device['name'],
                                'config': config_data,
                                'vendor': device.get('device_type', {}).get('manufacturer', {}).get('name', 'unknown')
                            })
            
            return configs
            
        except Exception as e:
            print(f"Failed to fetch configs from Nautobot: {e}")
            return []

class GitLabPlugin(BaseIntegrationPlugin):
    """GitLab integration plugin for config management."""
    
    @property
    def name(self) -> str:
        return "gitlab"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def __init__(self):
        self.base_url = None
        self.api_token = None
        self.project_id = None
        self.session = None
    
    async def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize GitLab connection."""
        try:
            import aiohttp
            
            self.base_url = config.get('base_url')
            self.api_token = config.get('api_token')
            self.project_id = config.get('project_id')
            
            if not all([self.base_url, self.api_token, self.project_id]):
                return False
            
            self.session = aiohttp.ClientSession(
                headers={'PRIVATE-TOKEN': self.api_token}
            )
            
            # Test connection
            async with self.session.get(f"{self.base_url}/api/v4/projects/{self.project_id}") as response:
                return response.status == 200
                
        except Exception as e:
            print(f"GitLab initialization failed: {e}")
            return False
    
    async def send_results(self, results: List[ComplianceResult]) -> bool:
        """Create GitLab issues for non-compliant devices."""
        try:
            for result in results:
                if not result.compliant:
                    # Create issue for non-compliant device
                    failed_checks = [
                        control for control, data in result.checks.items()
                        if not data.get('passed', False)
                    ]
                    
                    issue_data = {
                        'title': f"CMMC Compliance Issue: {result.hostname}",
                        'description': f"""
## Compliance Issue Report

**Device:** {result.hostname}
**Vendor:** {result.vendor_display}
**Version:** {result.detected_version or 'Unknown'}
**Compliance Rate:** {result.compliance_rate:.1f}%
**Timestamp:** {result.timestamp}

### Failed Controls:
{chr(10).join(f"- {control}" for control in failed_checks)}

### Recommended Actions:
Please review the compliance report and apply necessary remediation.

---
*Generated by CMMC Compliance Tool*
                        """,
                        'labels': ['compliance', 'security', 'cmmc', f'vendor-{result.vendor_type}']
                    }
                    
                    # Create issue
                    url = f"{self.base_url}/api/v4/projects/{self.project_id}/issues"
                    async with self.session.post(url, json=issue_data) as response:
                        if response.status not in [200, 201]:
                            print(f"Failed to create GitLab issue for {result.hostname}")
                            return False
            
            return True
            
        except Exception as e:
            print(f"Failed to send results to GitLab: {e}")
            return False
    
    async def fetch_configs(self, device_filters: Dict[str, Any]) -> List[Dict[str, str]]:
        """Fetch configurations from GitLab repository."""
        try:
            configs = []
            config_path = device_filters.get('config_path', 'configs')
            
            # Get repository files
            url = f"{self.base_url}/api/v4/projects/{self.project_id}/repository/tree"
            params = {'path': config_path, 'recursive': True}
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    files = await response.json()
                    
                    # Filter config files
                    config_files = [f for f in files if f['name'].endswith(('.cfg', '.conf', '.txt'))]
                    
                    for file_info in config_files:
                        # Get file content
                        file_url = f"{self.base_url}/api/v4/projects/{self.project_id}/repository/files/{file_info['path']}"
                        params = {'ref': 'main'}
                        
                        async with self.session.get(file_url, params=params) as file_response:
                            if file_response.status == 200:
                                file_data = await file_response.json()
                                
                                # Decode base64 content
                                import base64
                                config_content = base64.b64decode(file_data['content']).decode('utf-8')
                                
                                configs.append({
                                    'hostname': file_info['name'].replace('.cfg', ''),
                                    'config': config_content,
                                    'file_path': file_info['path']
                                })
            
            return configs
            
        except Exception as e:
            print(f"Failed to fetch configs from GitLab: {e}")
            return []

class SplunkPlugin(BaseIntegrationPlugin):
    """Splunk integration plugin for logging and analytics."""
    
    @property
    def name(self) -> str:
        return "splunk"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def __init__(self):
        self.base_url = None
        self.username = None
        self.password = None
        self.index = None
        self.session = None
        self.session_key = None
    
    async def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize Splunk connection."""
        try:
            import aiohttp
            
            self.base_url = config.get('base_url')
            self.username = config.get('username')
            self.password = config.get('password')
            self.index = config.get('index', 'cmmc_compliance')
            
            if not all([self.base_url, self.username, self.password]):
                return False
            
            self.session = aiohttp.ClientSession()
            
            # Authenticate and get session key
            auth_url = f"{self.base_url}/services/auth/login"
            auth_data = {
                'username': self.username,
                'password': self.password
            }
            
            async with self.session.post(auth_url, data=auth_data) as response:
                if response.status == 200:
                    # Parse session key from XML response
                    content = await response.text()
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(content)
                    self.session_key = root.find('.//sessionKey').text
                    return True
                    
            return False
                
        except Exception as e:
            print(f"Splunk initialization failed: {e}")
            return False
    
    async def send_results(self, results: List[ComplianceResult]) -> bool:
        """Send compliance results to Splunk for indexing."""
        try:
            for result in results:
                # Create Splunk event
                event_data = {
                    'time': result.timestamp.timestamp(),
                    'source': 'cmmc_compliance_tool',
                    'sourcetype': 'cmmc:compliance',
                    'index': self.index,
                    'event': {
                        'hostname': result.hostname,
                        'vendor_type': result.vendor_type,
                        'vendor_display': result.vendor_display,
                        'detected_version': result.detected_version,
                        'compliant': result.compliant,
                        'compliance_rate': result.compliance_rate,
                        'checks': result.checks,
                        'job_id': result.job_id
                    }
                }
                
                # Send to Splunk HTTP Event Collector
                hec_url = f"{self.base_url}/services/collector/event"
                headers = {
                    'Authorization': f'Splunk {self.session_key}',
                    'Content-Type': 'application/json'
                }
                
                async with self.session.post(hec_url, json=event_data, headers=headers) as response:
                    if response.status not in [200, 201]:
                        print(f"Failed to send event to Splunk for {result.hostname}")
                        return False
            
            return True
            
        except Exception as e:
            print(f"Failed to send results to Splunk: {e}")
            return False
    
    async def fetch_configs(self, device_filters: Dict[str, Any]) -> List[Dict[str, str]]:
        """Fetch configurations from Splunk (if stored there)."""
        # This would be less common, but could search for stored configs
        return []

# Plugin manager
class PluginManager:
    """Manages integration plugins."""
    
    def __init__(self):
        self.plugins: Dict[str, BaseIntegrationPlugin] = {}
        self.plugin_configs: Dict[str, Dict[str, Any]] = {}
    
    def register_plugin(self, plugin: BaseIntegrationPlugin):
        """Register a plugin."""
        self.plugins[plugin.name] = plugin
    
    async def initialize_plugin(self, plugin_name: str, config: Dict[str, Any]) -> bool:
        """Initialize a specific plugin."""
        if plugin_name in self.plugins:
            self.plugin_configs[plugin_name] = config
            return await self.plugins[plugin_name].initialize(config)
        return False
    
    async def send_results_to_all(self, results: List[ComplianceResult]) -> Dict[str, bool]:
        """Send results to all initialized plugins."""
        results_status = {}
        
        for plugin_name, plugin in self.plugins.items():
            if plugin_name in self.plugin_configs:
                try:
                    success = await plugin.send_results(results)
                    results_status[plugin_name] = success
                except Exception as e:
                    print(f"Error sending to {plugin_name}: {e}")
                    results_status[plugin_name] = False
        
        return results_status
    
    def get_available_plugins(self) -> List[Dict[str, str]]:
        """Get list of available plugins."""
        return [
            {'name': plugin.name, 'version': plugin.version}
            for plugin in self.plugins.values()
        ]

# FastAPI application
app = FastAPI(
    title="CMMC Compliance API",
    description="RESTful API for CMMC 2.0 Level 1 compliance checking with multi-vendor support",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
job_store: Dict[str, JobStatus] = {}
plugin_manager = PluginManager()

# Initialize plugins
@app.on_event("startup")
async def startup_event():
    """Initialize plugins on startup."""
    
    # Register available plugins
    plugin_manager.register_plugin(NautobotPlugin())
    plugin_manager.register_plugin(GitLabPlugin())
    plugin_manager.register_plugin(SplunkPlugin())
    
    # Load plugin configurations from environment or config file
    # This would typically come from environment variables or config file
    print("CMMC Compliance API started")
    print(f"Available plugins: {[p['name'] for p in plugin_manager.get_available_plugins()]}")

# API endpoints
@app.get("/")
async def root():
    """API root endpoint."""
    return {
        "message": "CMMC Compliance API",
        "version": "1.0.0",
        "available_plugins": plugin_manager.get_available_plugins()
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now()}

@app.post("/compliance/check", response_model=JobStatus)
async def start_compliance_check(
    request: ComplianceRequest,
    background_tasks: BackgroundTasks
):
    """Start a compliance check job."""
    
    job_id = str(uuid.uuid4())
    
    # Create job status
    job_status = JobStatus(
        job_id=job_id,
        status="pending",
        progress=0.0,
        message="Job queued",
        created_at=datetime.now()
    )
    
    job_store[job_id] = job_status
    
    # Start background task
    background_tasks.add_task(
        run_compliance_check,
        job_id,
        request
    )
    
    return job_status

@app.get("/compliance/status/{job_id}", response_model=JobStatus)
async def get_job_status(job_id: str):
    """Get status of a compliance check job."""
    
    if job_id not in job_store:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return job_store[job_id]

@app.get("/compliance/results/{job_id}")
async def get_job_results(job_id: str):
    """Get results of a completed compliance check job."""
    
    if job_id not in job_store:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = job_store[job_id]
    if job.status != "completed":
        raise HTTPException(status_code=400, detail="Job not completed")
    
    return {
        "job_id": job_id,
        "results": job.results,
        "summary": {
            "total_devices": len(job.results) if job.results else 0,
            "compliant_devices": sum(1 for r in job.results if r.compliant) if job.results else 0
        }
    }

@app.post("/plugins/{plugin_name}/configure")
async def configure_plugin(plugin_name: str, config: Dict[str, Any]):
    """Configure a specific plugin."""
    
    success = await plugin_manager.initialize_plugin(plugin_name, config)
    
    if success:
        return {"message": f"Plugin {plugin_name} configured successfully"}
    else:
        raise HTTPException(status_code=400, detail=f"Failed to configure plugin {plugin_name}")

@app.get("/plugins")
async def list_plugins():
    """List available plugins."""
    return {
        "available_plugins": plugin_manager.get_available_plugins(),
        "configured_plugins": list(plugin_manager.plugin_configs.keys())
    }

@app.post("/integrations/fetch-configs")
async def fetch_configs_from_integrations(
    plugin_name: str,
    filters: Dict[str, Any] = {}
):
    """Fetch device configurations from integrated systems."""
    
    if plugin_name not in plugin_manager.plugins:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    if plugin_name not in plugin_manager.plugin_configs:
        raise HTTPException(status_code=400, detail="Plugin not configured")
    
    plugin = plugin_manager.plugins[plugin_name]
    configs = await plugin.fetch_configs(filters)
    
    return {
        "plugin": plugin_name,
        "configs_found": len(configs),
        "configs": configs
    }

# Background task for compliance checking
async def run_compliance_check(job_id: str, request: ComplianceRequest):
    """Run compliance check in background."""
    
    try:
        # Update job status
        job_store[job_id].status = "running"
        job_store[job_id].message = "Starting compliance check"
        
        # Import necessary modules
        from enhanced_features.vendor_manager import VendorManager, VendorType
        
        vendor_manager = VendorManager()
        results = []
        
        total_configs = len(request.device_configs)
        
        for i, config_content in enumerate(request.device_configs):
            # Update progress
            progress = (i / total_configs) * 100
            job_store[job_id].progress = progress
            job_store[job_id].message = f"Processing device {i+1}/{total_configs}"
            
            # Determine vendor type
            vendor_type = None
            if request.vendor_type:
                vendor_type = VendorType(request.vendor_type)
            
            # Run compliance check
            compliance_result = vendor_manager.check_compliance_multi_vendor(
                config_content, vendor_type
            )
            
            # Convert to API model
            api_result = ComplianceResult(
                job_id=job_id,
                hostname=compliance_result.get('hostname', 'Unknown'),
                vendor_type=compliance_result.get('vendor_type', 'unknown'),
                vendor_display=compliance_result.get('vendor_display', 'Unknown'),
                detected_version=compliance_result.get('detected_version'),
                compliant=compliance_result.get('compliant', False),
                compliance_rate=calculate_compliance_rate(compliance_result.get('checks', {})),
                checks=compliance_result.get('checks', {}),
                timestamp=datetime.now()
            )
            
            results.append(api_result)
        
        # Send results to configured plugins
        if results:
            plugin_results = await plugin_manager.send_results_to_all(results)
            print(f"Plugin integration results: {plugin_results}")
        
        # Complete job
        job_store[job_id].status = "completed"
        job_store[job_id].progress = 100.0
        job_store[job_id].message = "Compliance check completed"
        job_store[job_id].completed_at = datetime.now()
        job_store[job_id].results = results
        
    except Exception as e:
        # Handle errors
        job_store[job_id].status = "failed"
        job_store[job_id].message = f"Error: {str(e)}"
        print(f"Compliance check failed for job {job_id}: {e}")

def calculate_compliance_rate(checks: Dict[str, Any]) -> float:
    """Calculate compliance rate from check results."""
    if not checks:
        return 0.0
    
    passed_checks = sum(1 for check in checks.values() if check.get('passed', False))
    total_checks = len(checks)
    
    return (passed_checks / total_checks) * 100 if total_checks > 0 else 0.0

# Configuration management
class APIConfig:
    """API configuration management."""
    
    @staticmethod
    def load_config():
        """Load configuration from file or environment."""
        config_file = Path("api_config.json")
        
        if config_file.exists():
            with open(config_file) as f:
                return json.load(f)
        
        # Default configuration
        return {
            "host": "0.0.0.0",
            "port": 8000,
            "plugins": {
                "nautobot": {
                    "enabled": False,
                    "base_url": "",
                    "api_token": ""
                },
                "gitlab": {
                    "enabled": False,
                    "base_url": "",
                    "api_token": "",
                    "project_id": ""
                },
                "splunk": {
                    "enabled": False,
                    "base_url": "",
                    "username": "",
                    "password": "",
                    "index": "cmmc_compliance"
                }
            }
        }

# CLI for running the API
def run_api():
    """Run the API server."""
    config = APIConfig.load_config()
    
    uvicorn.run(
        "api.cmmc_api:app",
        host=config.get("host", "0.0.0.0"),
        port=config.get("port", 8000),
        reload=True
    )

if __name__ == "__main__":
    run_api()

# Example API client
class CMMCAPIClient:
    """Client for interacting with CMMC API."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
    
    async def start_compliance_check(self, device_configs: List[str], vendor_type: str = None) -> str:
        """Start a compliance check and return job ID."""
        import aiohttp
        
        request_data = {
            "device_configs": device_configs,
            "baseline_configs": device_configs,  # For demo
            "vendor_type": vendor_type,
            "skip_connectivity": True,
            "generate_reports": True
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{self.base_url}/compliance/check", json=request_data) as response:
                if response.status == 200:
                    result = await response.json()
                    return result["job_id"]
                else:
                    raise Exception(f"API request failed: {response.status}")
    
    async def get_results(self, job_id: str) -> Dict:
        """Get compliance check results."""
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.base_url}/compliance/results/{job_id}") as response:
                if response.status == 200:
                    return await response.json()
                else:
                    raise Exception(f"API request failed: {response.status}")

# Usage example
async def example_usage():
    """Example of how to use the API."""
    
    # Example configuration content
    cisco_config = """
    hostname ExampleRouter
    version 15.7
    aaa authentication login default group tacacs+ local
    tacacs-server host 192.168.1.100 key secretkey
    enable secret 5 $1$example$hash
    line vty 0 4
     transport input ssh
     access-class MGMT-ACL in
    """
    
    # Create API client
    client = CMMCAPIClient()
    
    # Start compliance check
    job_id = await client.start_compliance_check([cisco_config], "cisco_ios")
    print(f"Started job: {job_id}")
    
    # Wait for completion and get results
    import asyncio
    await asyncio.sleep(5)  # Wait for job to complete
    
    results = await client.get_results(job_id)
    print(f"Results: {results}")

# Integration examples
def setup_nautobot_integration():
    """Example of setting up Nautobot integration."""
    return {
        "base_url": "https://nautobot.example.com",
        "api_token": "your_nautobot_api_token_here",
        "custom_fields": {
            "compliance_status": "cmmc_compliance_status",
            "compliance_rate": "cmmc_compliance_rate",
            "last_check": "cmmc_last_check"
        }
    }

def setup_gitlab_integration():
    """Example of setting up GitLab integration."""
    return {
        "base_url": "https://gitlab.example.com",
        "api_token": "your_gitlab_api_token_here",
        "project_id": "123",
        "config_branch": "main",
        "config_path": "network_configs"
    }

def setup_splunk_integration():
    """Example of setting up Splunk integration."""
    return {
        "base_url": "https://splunk.example.com:8089",
        "username": "cmmc_service_account",
        "password": "secure_password",
        "index": "network_security",
        "hec_token": "your_hec_token_here"
    }