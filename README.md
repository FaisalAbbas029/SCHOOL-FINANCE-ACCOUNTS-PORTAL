The Smart School System — Finance & Accounts PortalAcademic Session 2025–2026
Role-Based Financial & Administrative Gateway with Strict Audit Integrity & Multi-Tier Oversight.

🌟 OverviewThe Smart School System is an enterprise-grade financial management and administrative portal built specifically for educational institutions. It enforces a strict separation of duties, ensuring transparent record-keeping for student fee structures and vendor supply chains while maintaining uncompromised financial audit trails.

🛠️ Technology StackFrontend:React.js (Functional Components & Hooks)Tailwind CSS (Custom-matched to official Smart School brand palette: Crimson #D32F2F, Charcoal Gray, Off-White)Lucide React (Icons)Recharts (Financial analytics & visual data distribution)Axios (API Client)Backend:Python & Django FrameworkDjango REST Framework (DRF)Token / Session Authentication & Custom Permission ClassesSQLite / PostgreSQL database support👥 Role-Based Access Control (RBAC) & PermissionsRoleAccess LevelCore Responsibilities & ConstraintsGM / Super AdminFull System & OversightOversees entire institution. Can add, manage, and remove Accountants and HODs. 

⚠️ Anti-Tampering Rule: Read-only audit access to original accountant financial logs (cannot modify original entries). Can view own + accountant audit logs.HOD / AdminDepartmental OversightReviews departmental reports and authorized summaries. Read-only access to financial ledgers. Can view accountant audit logs only.Senior AccountantPrimary Data EntryOperates data entry modules for Student Data (Cat 1) and Vendor Payables (Cat 2) with structured date/month/year tracking. Can edit self-submitted logs and view personal audit entries.Vendor PortalIsolated Supplier ViewDedicated secure interface for authorized suppliers to review invoice balances and payment statuses.🔒 Security & Authentication FlowEmbedded Profile Controls: Sign-in, session management, and credential updates integrated directly into the user profile dropdown.Default Super Admin Credentials:Email: faisalabbas@gmail.comDefault Password: faisal@123First-Time Password Reset: Accounts provisioned with temporary passwords are required to update credentials upon initial login.Profile Customization: Users can upload, store, and preview custom avatar profile pictures across the header navigation and profile modals.Hierarchical Audit Trail: Log visibility is restricted based on hierarchy (Accountant sees self logs; HOD sees Accountant logs; Super Admin sees Super Admin + Accountant logs).📂 Repository Structurethe-smart-school-system/
│
├── backend/                  # Django REST Framework Backend
│   ├── authentication/       # Custom User Model & Auth Endpoints
│   ├── financials/           # Student Fees & Vendor Payables Models
│   ├── audit_logs/           # Role-filtered Audit Trail API
│   ├── manage.py
│   └── requirements.txt
│
└── frontend/                 # React.js Frontend Application
    ├── public/               # Static assets & brand logos
    ├── src/
    │   ├── components/       # Reusable UI cards, tables, modals
    │   ├── layouts/          # Responsive Sidebar & Top Navigation bar
    │   ├── views/            # GM, HOD, Accountant & Vendor Dashboards
    │   ├── App.jsx           # Main routing & state controller
    │   └── index.css         # Tailwind & custom styling definitions
    ├── package.json
    └── tailwind.config.js
🚀 Getting Started & Local InstallationPrerequisitesPython 3.10+ installedNode.js (v18+) & npm installedGit1. Clone the Repositorygit clone https://github.com/your-username/the-smart-school-system.git
cd the-smart-school-system
2. Backend Setup (Django)cd backend
python -m venv venv
# Activate virtual environment:
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
python manage.py makemigrations
python manage.py migrate
python manage.py runserver
(Backend server runs by default at http://127.0.0.1:8000/)3. Frontend Setup (React.js)Open a new terminal window and navigate to the frontend directory:cd frontend
npm install
npm run dev
(Frontend development server runs by default at http://localhost:5173/)📄 LicenseDistributed under the MIT License. See LICENSE for more information.
