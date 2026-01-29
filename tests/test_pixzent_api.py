"""
PixZent API Backend Tests
Tests for: Health, Auth, Audit Submissions, Admin APIs
"""
import pytest
import requests
import os
import uuid

# Get backend URL from environment - fallback to production URL
BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', 'https://aeo-optimize.preview.emergentagent.com').rstrip('/')

# Test credentials
ADMIN_EMAIL = "dmb@pixzent.com"
ADMIN_PASSWORD = "uaepixzent@#2026@$"


class TestHealthEndpoints:
    """Health check endpoint tests"""
    
    def test_root_endpoint(self):
        """Test root API endpoint"""
        response = requests.get(f"{BASE_URL}/api/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "PixZent" in data["message"]
    
    def test_health_endpoint(self):
        """Test health check endpoint"""
        response = requests.get(f"{BASE_URL}/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data


class TestAuthEndpoints:
    """Authentication endpoint tests"""
    
    def test_login_success(self):
        """Test successful admin login"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data
        assert len(data["access_token"]) > 0
    
    def test_login_invalid_email(self):
        """Test login with invalid email"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "wrong@example.com",
            "password": ADMIN_PASSWORD
        })
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
    
    def test_login_invalid_password(self):
        """Test login with invalid password"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": "wrongpassword"
        })
        assert response.status_code == 401
    
    def test_verify_token_valid(self):
        """Test token verification with valid token"""
        # First login to get token
        login_response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        token = login_response.json()["access_token"]
        
        # Verify token
        response = requests.get(
            f"{BASE_URL}/api/auth/verify",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] == True
        assert data["email"] == ADMIN_EMAIL
    
    def test_verify_token_invalid(self):
        """Test token verification with invalid token"""
        response = requests.get(
            f"{BASE_URL}/api/auth/verify",
            headers={"Authorization": "Bearer invalid_token_here"}
        )
        assert response.status_code == 401


class TestAuditSubmissionPublic:
    """Public audit submission endpoint tests"""
    
    def test_create_submission_success(self):
        """Test creating a new audit submission"""
        unique_id = str(uuid.uuid4())[:8]
        payload = {
            "full_name": f"TEST_User_{unique_id}",
            "business_name": f"TEST_Business_{unique_id}",
            "website_url": f"https://test-{unique_id}.com",
            "email": f"test_{unique_id}@example.com",
            "phone": "+1234567890",
            "location": "Test City",
            "industry": "Technology",
            "challenge": "Testing audit submission",
            "source": "Website"
        }
        
        response = requests.post(f"{BASE_URL}/api/audit-submissions", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert data["full_name"] == payload["full_name"]
        assert data["email"] == payload["email"]
        assert data["website_url"] == payload["website_url"]
        assert data["status"] == "New"
        assert "id" in data
        assert "created_at" in data
        
        # Store ID for cleanup
        return data["id"]
    
    def test_create_submission_minimal_fields(self):
        """Test creating submission with minimal required fields"""
        unique_id = str(uuid.uuid4())[:8]
        payload = {
            "full_name": f"TEST_Minimal_{unique_id}",
            "website_url": f"https://minimal-{unique_id}.com",
            "email": f"minimal_{unique_id}@example.com",
            "phone": "+1234567890",
            "industry": "Healthcare"
        }
        
        response = requests.post(f"{BASE_URL}/api/audit-submissions", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert data["full_name"] == payload["full_name"]
        assert data["source"] == "Website"  # Default source
    
    def test_create_submission_chatbot_source(self):
        """Test creating submission from chatbot"""
        unique_id = str(uuid.uuid4())[:8]
        payload = {
            "full_name": f"TEST_Chatbot_{unique_id}",
            "website_url": "Via Chatbot",
            "email": f"chatbot_{unique_id}@example.com",
            "phone": "+1234567890",
            "industry": "E-commerce",
            "source": "Chatbot"
        }
        
        response = requests.post(f"{BASE_URL}/api/audit-submissions", json=payload)
        assert response.status_code == 200
        
        data = response.json()
        assert data["source"] == "Chatbot"
    
    def test_create_submission_invalid_email(self):
        """Test creating submission with invalid email"""
        payload = {
            "full_name": "Test User",
            "website_url": "https://test.com",
            "email": "invalid-email",  # Invalid email format
            "phone": "+1234567890",
            "industry": "Technology"
        }
        
        response = requests.post(f"{BASE_URL}/api/audit-submissions", json=payload)
        assert response.status_code == 422  # Validation error


class TestAdminSubmissionEndpoints:
    """Admin submission management endpoint tests"""
    
    @pytest.fixture
    def auth_token(self):
        """Get authentication token"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        return response.json()["access_token"]
    
    @pytest.fixture
    def auth_headers(self, auth_token):
        """Get headers with auth token"""
        return {"Authorization": f"Bearer {auth_token}"}
    
    @pytest.fixture
    def test_submission(self, auth_headers):
        """Create a test submission and return its ID"""
        unique_id = str(uuid.uuid4())[:8]
        payload = {
            "full_name": f"TEST_Admin_{unique_id}",
            "website_url": f"https://admin-test-{unique_id}.com",
            "email": f"admin_test_{unique_id}@example.com",
            "phone": "+1234567890",
            "industry": "Finance",
            "source": "Website"
        }
        
        response = requests.post(f"{BASE_URL}/api/audit-submissions", json=payload)
        submission_id = response.json()["id"]
        
        yield submission_id
        
        # Cleanup - delete the test submission
        requests.delete(
            f"{BASE_URL}/api/admin/submissions/{submission_id}",
            headers=auth_headers
        )
    
    def test_get_all_submissions(self, auth_headers):
        """Test getting all submissions"""
        response = requests.get(
            f"{BASE_URL}/api/admin/submissions",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    def test_get_all_submissions_unauthorized(self):
        """Test getting submissions without auth"""
        response = requests.get(f"{BASE_URL}/api/admin/submissions")
        assert response.status_code in [401, 403]
    
    def test_get_single_submission(self, auth_headers, test_submission):
        """Test getting a single submission by ID"""
        response = requests.get(
            f"{BASE_URL}/api/admin/submissions/{test_submission}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == test_submission
        # Verify tracking fields exist
        assert "ip_address" in data
        assert "user_agent" in data
        assert "referrer" in data
        assert "page_url" in data
    
    def test_get_submission_not_found(self, auth_headers):
        """Test getting non-existent submission"""
        response = requests.get(
            f"{BASE_URL}/api/admin/submissions/non-existent-id",
            headers=auth_headers
        )
        assert response.status_code == 404
    
    def test_update_submission_status(self, auth_headers, test_submission):
        """Test updating submission status"""
        # Update to In Progress
        response = requests.patch(
            f"{BASE_URL}/api/admin/submissions/{test_submission}",
            headers=auth_headers,
            json={"status": "In Progress"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "In Progress"
        
        # Verify with GET
        get_response = requests.get(
            f"{BASE_URL}/api/admin/submissions/{test_submission}",
            headers=auth_headers
        )
        assert get_response.json()["status"] == "In Progress"
    
    def test_update_submission_notes(self, auth_headers, test_submission):
        """Test updating submission notes"""
        notes = "Test notes for this submission"
        response = requests.patch(
            f"{BASE_URL}/api/admin/submissions/{test_submission}",
            headers=auth_headers,
            json={"notes": notes}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["notes"] == notes
    
    def test_update_submission_audit_sent(self, auth_headers, test_submission):
        """Test marking audit as sent"""
        response = requests.patch(
            f"{BASE_URL}/api/admin/submissions/{test_submission}",
            headers=auth_headers,
            json={
                "audit_sent": True,
                "status": "Completed"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["audit_sent"] == True
        assert data["status"] == "Completed"
    
    def test_delete_submission(self, auth_headers):
        """Test deleting a submission"""
        # Create a submission to delete
        unique_id = str(uuid.uuid4())[:8]
        create_response = requests.post(
            f"{BASE_URL}/api/audit-submissions",
            json={
                "full_name": f"TEST_Delete_{unique_id}",
                "website_url": f"https://delete-{unique_id}.com",
                "email": f"delete_{unique_id}@example.com",
                "phone": "+1234567890",
                "industry": "Technology"
            }
        )
        submission_id = create_response.json()["id"]
        
        # Delete it
        delete_response = requests.delete(
            f"{BASE_URL}/api/admin/submissions/{submission_id}",
            headers=auth_headers
        )
        assert delete_response.status_code == 200
        
        # Verify it's deleted
        get_response = requests.get(
            f"{BASE_URL}/api/admin/submissions/{submission_id}",
            headers=auth_headers
        )
        assert get_response.status_code == 404


class TestAdminStatsEndpoint:
    """Admin stats endpoint tests"""
    
    @pytest.fixture
    def auth_headers(self):
        """Get headers with auth token"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        token = response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    
    def test_get_stats(self, auth_headers):
        """Test getting admin stats"""
        response = requests.get(
            f"{BASE_URL}/api/admin/stats",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        
        # Verify stats structure
        assert "total" in data
        assert "new" in data
        assert "in_progress" in data
        assert "completed" in data
        assert "by_source" in data
        assert "website" in data["by_source"]
        assert "chatbot" in data["by_source"]
        
        # Verify types
        assert isinstance(data["total"], int)
        assert isinstance(data["new"], int)
    
    def test_get_stats_unauthorized(self):
        """Test getting stats without auth"""
        response = requests.get(f"{BASE_URL}/api/admin/stats")
        assert response.status_code in [401, 403]


class TestTrackingFields:
    """Tests for tracking field capture"""
    
    @pytest.fixture
    def auth_headers(self):
        """Get headers with auth token"""
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        token = response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    
    def test_utm_parameters_captured(self, auth_headers):
        """Test that UTM parameters are captured"""
        unique_id = str(uuid.uuid4())[:8]
        payload = {
            "full_name": f"TEST_UTM_{unique_id}",
            "website_url": f"https://utm-test-{unique_id}.com",
            "email": f"utm_{unique_id}@example.com",
            "phone": "+1234567890",
            "industry": "Marketing",
            "utm_source": "google",
            "utm_medium": "cpc",
            "utm_campaign": "test_campaign"
        }
        
        response = requests.post(f"{BASE_URL}/api/audit-submissions", json=payload)
        assert response.status_code == 200
        submission_id = response.json()["id"]
        
        # Get the submission and verify UTM params
        get_response = requests.get(
            f"{BASE_URL}/api/admin/submissions/{submission_id}",
            headers=auth_headers
        )
        data = get_response.json()
        
        assert data["utm_source"] == "google"
        assert data["utm_medium"] == "cpc"
        assert data["utm_campaign"] == "test_campaign"
        
        # Cleanup
        requests.delete(
            f"{BASE_URL}/api/admin/submissions/{submission_id}",
            headers=auth_headers
        )
    
    def test_ip_and_user_agent_captured(self, auth_headers):
        """Test that IP and user agent are captured"""
        unique_id = str(uuid.uuid4())[:8]
        payload = {
            "full_name": f"TEST_Tracking_{unique_id}",
            "website_url": f"https://tracking-{unique_id}.com",
            "email": f"tracking_{unique_id}@example.com",
            "phone": "+1234567890",
            "industry": "Technology"
        }
        
        # Send with custom user agent
        response = requests.post(
            f"{BASE_URL}/api/audit-submissions",
            json=payload,
            headers={"User-Agent": "TestBot/1.0"}
        )
        assert response.status_code == 200
        submission_id = response.json()["id"]
        
        # Get the submission and verify tracking
        get_response = requests.get(
            f"{BASE_URL}/api/admin/submissions/{submission_id}",
            headers=auth_headers
        )
        data = get_response.json()
        
        # IP should be captured (may be proxy IP)
        assert data["ip_address"] is not None
        # User agent should be captured
        assert data["user_agent"] is not None
        
        # Cleanup
        requests.delete(
            f"{BASE_URL}/api/admin/submissions/{submission_id}",
            headers=auth_headers
        )


# Cleanup function to remove TEST_ prefixed data
def cleanup_test_data():
    """Remove all test data created during tests"""
    try:
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Get all submissions
        submissions = requests.get(
            f"{BASE_URL}/api/admin/submissions",
            headers=headers
        ).json()
        
        # Delete TEST_ prefixed submissions
        for sub in submissions:
            if sub.get("full_name", "").startswith("TEST_"):
                requests.delete(
                    f"{BASE_URL}/api/admin/submissions/{sub['id']}",
                    headers=headers
                )
                print(f"Cleaned up: {sub['full_name']}")
    except Exception as e:
        print(f"Cleanup error: {e}")


if __name__ == "__main__":
    # Run cleanup before tests
    cleanup_test_data()
    pytest.main([__file__, "-v", "--tb=short"])
