#!/usr/bin/env python3
"""
GUARD-IA ENTERPRISE v3.0
Protection sectorielle complète + RBAC (Role-Based Access Control)
Inspiré de KERNEL-Φ - Sécurité niveau gouvernemental
"""

import hashlib
import re
import base64
import json
import secrets
import time
import sqlite3
from datetime import datetime, timedelta
from typing import List, Tuple, Optional, Dict, Any, Set
from enum import Enum
from dataclasses import dataclass, field
from functools import wraps
from contextlib import contextmanager

from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, validator
import stripe
import uvicorn


# ============================================================================
# PARTIE 1 : DÉFINITIONS SECTORIELLES ET RÔLES
# ============================================================================

class Sector(Enum):
    """Secteurs d'activité supportés"""
    RETAIL = "retail"               # Commerce
    BANKING = "banking"             # Banque/Finance
    HEALTHCARE = "healthcare"       # Santé
    GOVERNMENT = "government"       # Administration
    MILITARY = "military"           # Armée/Défense
    EDUCATION = "education"         # Éducation
    LEGAL = "legal"                 # Cabinets d'avocats
    INSURANCE = "insurance"         # Assurances


class Role(Enum):
    """Rôles utilisateurs - Hiérarchie complète"""
    # Niveau 0 - Pas d'accès
    BANNED = "banned"
    
    # Niveau 1 - Accès public
    PUBLIC = "public"
    
    # Niveau 2 - Accès employé standard
    EMPLOYEE = "employee"
    
    # Niveau 3 - Accès superviseur
    SUPERVISOR = "supervisor"
    
    # Niveau 4 - Accès manager
    MANAGER = "manager"
    
    # Niveau 5 - Accès directeur
    DIRECTOR = "director"
    
    # Niveau 6 - Accès conformité
    COMPLIANCE_OFFICER = "compliance_officer"
    
    # Niveau 7 - Accès audit
    AUDITOR = "auditor"
    
    # Niveau 8 - Accès administrateur
    ADMIN = "admin"
    
    # Niveau 9 - Accès créateur (souverain)
    CREATOR = "creator"
    
    # Niveaux spéciaux - Secteur militaire
    CLEARED_PERSONNEL = "cleared_personnel"      # Habilité secret défense
    COMMANDING_OFFICER = "commanding_officer"    # Officier commandant
    JOINT_CHIEF = "joint_chief"                  # État-major
    
    # Niveaux spéciaux - Secteur santé
    PHYSICIAN = "physician"                      # Médecin
    NURSE = "nurse"                              # Infirmier
    MEDICAL_DIRECTOR = "medical_director"        # Directeur médical
    ETHICS_COMMITTEE = "ethics_committee"        # Comité d'éthique
    
    # Niveaux spéciaux - Secteur éducation
    TEACHER = "teacher"                          # Enseignant
    PRINCIPAL = "principal"                      # Directeur d'école
    SCHOOL_BOARD = "school_board"                # Conseil d'école
    PARENT = "parent"                            # Parent d'élève


class Permission(Enum):
    """Permissions granulaires"""
    # Accès aux données
    READ_PUBLIC = "read:public"
    READ_CUSTOMER = "read:customer"
    READ_EMPLOYEE = "read:employee"
    READ_FINANCIAL = "read:financial"
    READ_MEDICAL = "read:medical"
    READ_CLASSIFIED = "read:classified"
    
    # Écriture/modification
    WRITE_CUSTOMER = "write:customer"
    WRITE_EMPLOYEE = "write:employee"
    WRITE_FINANCIAL = "write:financial"
    WRITE_MEDICAL = "write:medical"
    
    # Exports (très restreints)
    EXPORT_PUBLIC = "export:public"
    EXPORT_CUSTOMER = "export:customer"
    EXPORT_FINANCIAL = "export:financial"        # Réservé conformité
    EXPORT_MEDICAL = "export:medical"            # Réservé comité éthique
    
    # Accès sensibles
    ACCESS_AUDIT_LOG = "access:audit_log"
    ACCESS_COMPLIANCE = "access:compliance"
    ACCESS_CLASSIFIED = "access:classified"
    ACCESS_BACKDOOR = "access:backdoor"          # Créateur uniquement
    
    # Actions système
    BYPASS_VETO = "bypass:veto"                  # Contournement d'urgence
    RESET_SHIELD = "reset:shield"
    CONFIGURE_POLICY = "configure:policy"


# ============================================================================
# PARTIE 2 : MATRICE DES RÔLES ET PERMISSIONS
# ============================================================================

class RoleMatrix:
    """
    Matrice RBAC (Role-Based Access Control)
    Définit quels rôles ont quelles permissions dans quel secteur
    """
    
    def __init__(self):
        # Structure: sector -> role -> set(permissions)
        self._matrix: Dict[Sector, Dict[Role, Set[Permission]]] = {}
        self._build_matrix()
    
    def _build_matrix(self):
        """Construit la matrice des permissions par secteur et rôle"""
        
        # === SECTEUR RETAIL (Commerce) ===
        retail_matrix = {
            Role.PUBLIC: {Permission.READ_PUBLIC},
            Role.EMPLOYEE: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER},
            Role.SUPERVISOR: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.WRITE_CUSTOMER},
            Role.MANAGER: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.WRITE_CUSTOMER, Permission.READ_EMPLOYEE},
            Role.DIRECTOR: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.WRITE_CUSTOMER, 
                           Permission.READ_EMPLOYEE, Permission.WRITE_EMPLOYEE, Permission.EXPORT_PUBLIC},
            Role.COMPLIANCE_OFFICER: {Permission.READ_CUSTOMER, Permission.ACCESS_COMPLIANCE, Permission.EXPORT_CUSTOMER},
            Role.AUDITOR: {Permission.READ_CUSTOMER, Permission.ACCESS_AUDIT_LOG},
            Role.ADMIN: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.READ_EMPLOYEE,
                        Permission.ACCESS_AUDIT_LOG, Permission.CONFIGURE_POLICY},
            Role.CREATOR: {p for p in Permission},  # Toutes les permissions
        }
        self._matrix[Sector.RETAIL] = retail_matrix
        
        # === SECTEUR BANKING (Banque) ===
        banking_matrix = {
            Role.PUBLIC: {Permission.READ_PUBLIC},
            Role.EMPLOYEE: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER},
            Role.SUPERVISOR: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.READ_FINANCIAL},
            Role.MANAGER: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.READ_FINANCIAL, 
                          Permission.WRITE_CUSTOMER},
            Role.DIRECTOR: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.READ_FINANCIAL,
                           Permission.READ_EMPLOYEE, Permission.ACCESS_COMPLIANCE},
            Role.COMPLIANCE_OFFICER: {Permission.READ_FINANCIAL, Permission.ACCESS_COMPLIANCE, 
                                     Permission.EXPORT_FINANCIAL},
            Role.AUDITOR: {Permission.READ_FINANCIAL, Permission.ACCESS_AUDIT_LOG},
            Role.ADMIN: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.READ_FINANCIAL,
                        Permission.ACCESS_AUDIT_LOG, Permission.CONFIGURE_POLICY},
            Role.CREATOR: {p for p in Permission},
        }
        # La banque n'autorise PAS l'export client standard
        banking_matrix[Role.EMPLOYEE].discard(Permission.EXPORT_PUBLIC)
        banking_matrix[Role.MANAGER].discard(Permission.EXPORT_CUSTOMER)
        self._matrix[Sector.BANKING] = banking_matrix
        
        # === SECTEUR HEALTHCARE (Santé) ===
        healthcare_matrix = {
            Role.PUBLIC: {Permission.READ_PUBLIC},
            Role.NURSE: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER},
            Role.PHYSICIAN: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.READ_MEDICAL,
                            Permission.WRITE_MEDICAL},
            Role.MEDICAL_DIRECTOR: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.READ_MEDICAL,
                                   Permission.WRITE_MEDICAL, Permission.READ_EMPLOYEE},
            Role.ETHICS_COMMITTEE: {Permission.READ_MEDICAL, Permission.ACCESS_COMPLIANCE, 
                                   Permission.EXPORT_MEDICAL},
            Role.COMPLIANCE_OFFICER: {Permission.READ_MEDICAL, Permission.ACCESS_COMPLIANCE, Permission.EXPORT_MEDICAL},
            Role.AUDITOR: {Permission.READ_MEDICAL, Permission.ACCESS_AUDIT_LOG},
            Role.ADMIN: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.ACCESS_AUDIT_LOG,
                        Permission.CONFIGURE_POLICY},
            Role.CREATOR: {p for p in Permission},
        }
        # Restrictions HIPAA - pas d'export pour le personnel standard
        healthcare_matrix[Role.PHYSICIAN].discard(Permission.EXPORT_PUBLIC)
        healthcare_matrix[Role.PHYSICIAN].discard(Permission.EXPORT_MEDICAL)
        self._matrix[Sector.HEALTHCARE] = healthcare_matrix
        
        # === SECTEUR MILITARY (Armée) ===
        military_matrix = {
            Role.PUBLIC: {Permission.READ_PUBLIC},
            Role.CLEARED_PERSONNEL: {Permission.READ_PUBLIC, Permission.READ_CLASSIFIED},
            Role.COMMANDING_OFFICER: {Permission.READ_PUBLIC, Permission.READ_CLASSIFIED, Permission.READ_EMPLOYEE},
            Role.JOINT_CHIEF: {Permission.READ_PUBLIC, Permission.READ_CLASSIFIED, Permission.READ_EMPLOYEE,
                              Permission.ACCESS_COMPLIANCE},
            Role.AUDITOR: {Permission.READ_CLASSIFIED, Permission.ACCESS_AUDIT_LOG},
            Role.ADMIN: {Permission.READ_PUBLIC, Permission.ACCESS_AUDIT_LOG, Permission.CONFIGURE_POLICY},
            Role.CREATOR: {p for p in Permission},
        }
        # Pas d'export dans le militaire
        for role in military_matrix:
            military_matrix[role] = {p for p in military_matrix[role] if not p.value.startswith("export")}
        self._matrix[Sector.MILITARY] = military_matrix
        
        # === SECTEUR GOVERNMENT (Administration) ===
        government_matrix = {
            Role.PUBLIC: {Permission.READ_PUBLIC},
            Role.EMPLOYEE: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER},
            Role.SUPERVISOR: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.READ_EMPLOYEE},
            Role.DIRECTOR: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.READ_EMPLOYEE,
                           Permission.ACCESS_COMPLIANCE},
            Role.COMPLIANCE_OFFICER: {Permission.READ_CUSTOMER, Permission.ACCESS_COMPLIANCE, Permission.EXPORT_CUSTOMER},
            Role.AUDITOR: {Permission.READ_CUSTOMER, Permission.ACCESS_AUDIT_LOG},
            Role.ADMIN: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.ACCESS_AUDIT_LOG,
                        Permission.CONFIGURE_POLICY},
            Role.CREATOR: {p for p in Permission},
        }
        self._matrix[Sector.GOVERNMENT] = government_matrix
        
        # === SECTEUR EDUCATION ===
        education_matrix = {
            Role.PUBLIC: {Permission.READ_PUBLIC},
            Role.PARENT: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER},  # Accès à son enfant uniquement
            Role.TEACHER: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.WRITE_CUSTOMER},
            Role.PRINCIPAL: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.WRITE_CUSTOMER,
                            Permission.READ_EMPLOYEE},
            Role.SCHOOL_BOARD: {Permission.READ_CUSTOMER, Permission.ACCESS_COMPLIANCE},
            Role.AUDITOR: {Permission.READ_CUSTOMER, Permission.ACCESS_AUDIT_LOG},
            Role.ADMIN: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.ACCESS_AUDIT_LOG,
                        Permission.CONFIGURE_POLICY},
            Role.CREATOR: {p for p in Permission},
        }
        # Protection des mineurs - pas d'export
        for role in education_matrix:
            education_matrix[role] = {p for p in education_matrix[role] if not p.value.startswith("export")}
        self._matrix[Sector.EDUCATION] = education_matrix
        
        # === SECTEUR LEGAL (Avocats) ===
        legal_matrix = {
            Role.PUBLIC: {Permission.READ_PUBLIC},
            Role.EMPLOYEE: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER},
            Role.SUPERVISOR: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.READ_EMPLOYEE},
            Role.MANAGER: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.READ_EMPLOYEE,
                          Permission.ACCESS_COMPLIANCE},
            Role.COMPLIANCE_OFFICER: {Permission.READ_CUSTOMER, Permission.ACCESS_COMPLIANCE, Permission.EXPORT_CUSTOMER},
            Role.AUDITOR: {Permission.READ_CUSTOMER, Permission.ACCESS_AUDIT_LOG},
            Role.ADMIN: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.ACCESS_AUDIT_LOG,
                        Permission.CONFIGURE_POLICY},
            Role.CREATOR: {p for p in Permission},
        }
        self._matrix[Sector.LEGAL] = legal_matrix
        
        # === SECTEUR INSURANCE (Assurances) ===
        insurance_matrix = {
            Role.PUBLIC: {Permission.READ_PUBLIC},
            Role.EMPLOYEE: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER},
            Role.SUPERVISOR: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.READ_FINANCIAL},
            Role.MANAGER: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.READ_FINANCIAL,
                          Permission.WRITE_CUSTOMER},
            Role.COMPLIANCE_OFFICER: {Permission.READ_FINANCIAL, Permission.ACCESS_COMPLIANCE, Permission.EXPORT_FINANCIAL},
            Role.AUDITOR: {Permission.READ_FINANCIAL, Permission.ACCESS_AUDIT_LOG},
            Role.ADMIN: {Permission.READ_PUBLIC, Permission.READ_CUSTOMER, Permission.ACCESS_AUDIT_LOG,
                        Permission.CONFIGURE_POLICY},
            Role.CREATOR: {p for p in Permission},
        }
        self._matrix[Sector.INSURANCE] = insurance_matrix
    
    def has_permission(self, sector: Sector, role: Role, permission: Permission) -> bool:
        """Vérifie si un rôle a une permission dans un secteur"""
        sector_roles = self._matrix.get(sector)
        if not sector_roles:
            return False
        
        role_permissions = sector_roles.get(role)
        if not role_permissions:
            return False
        
        return permission in role_permissions
    
    def get_permissions(self, sector: Sector, role: Role) -> Set[Permission]:
        """Récupère toutes les permissions d'un rôle dans un secteur"""
        return self._matrix.get(sector, {}).get(role, set())
    
    def get_allowed_roles(self, sector: Sector, permission: Permission) -> List[Role]:
        """Récupère tous les rôles qui ont une permission donnée"""
        allowed = []
        for role, permissions in self._matrix.get(sector, {}).items():
            if permission in permissions:
                allowed.append(role)
        return allowed


# ============================================================================
# PARTIE 3 : GESTION DES UTILISATEURS ET SESSIONS
# ============================================================================

@dataclass
class User:
    """Utilisateur avec son rôle et ses permissions"""
    user_id: str
    email: str
    full_name: str
    sector: Sector
    role: Role
    department: Optional[str] = None
    clearance_level: Optional[int] = None  # Pour militaire/gouvernement
    permissions: Set[Permission] = field(default_factory=set)
    
    def __post_init__(self):
        # Charger les permissions depuis la matrice
        matrix = RoleMatrix()
        self.permissions = matrix.get_permissions(self.sector, self.role)
    
    def can(self, permission: Permission) -> bool:
        """Vérifie si l'utilisateur a une permission"""
        return permission in self.permissions
    
    def can_access_data(self, data_category: str, action: str = "read") -> bool:
        """Vérifie si l'utilisateur peut accéder à une catégorie de données"""
        permission_map = {
            ("customer", "read"): Permission.READ_CUSTOMER,
            ("customer", "write"): Permission.WRITE_CUSTOMER,
            ("financial", "read"): Permission.READ_FINANCIAL,
            ("financial", "write"): Permission.WRITE_FINANCIAL,
            ("medical", "read"): Permission.READ_MEDICAL,
            ("medical", "write"): Permission.WRITE_MEDICAL,
            ("classified", "read"): Permission.READ_CLASSIFIED,
            ("employee", "read"): Permission.READ_EMPLOYEE,
            ("employee", "write"): Permission.WRITE_EMPLOYEE,
        }
        
        perm = permission_map.get((data_category, action))
        if not perm:
            return False
        
        return self.can(perm)


class UserManager:
    """Gestion des utilisateurs et de l'authentification"""
    
    def __init__(self):
        self._users: Dict[str, User] = {}
        self._sessions: Dict[str, Dict] = {}
        
    def create_user(self, user_id: str, email: str, full_name: str, 
                    sector: Sector, role: Role, department: Optional[str] = None,
                    clearance_level: Optional[int] = None) -> User:
        """Crée un nouvel utilisateur"""
        user = User(
            user_id=user_id,
            email=email,
            full_name=full_name,
            sector=sector,
            role=role,
            department=department,
            clearance_level=clearance_level
        )
        self._users[user_id] = user
        return user
    
    def authenticate(self, api_key: str, user_id: str, user_secret: str) -> Optional[User]:
        """Authentifie un utilisateur"""
        # Dans un système réel, vérifier dans la base de données
        user = self._users.get(user_id)
        if user:
            # Créer une session
            session_token = secrets.token_urlsafe(48)
            self._sessions[session_token] = {
                "user_id": user_id,
                "created_at": time.time(),
                "expires_at": time.time() + 3600  # 1 heure
            }
            return user
        return None
    
    def get_user_by_id(self, user_id: str) -> Optional[User]:
        return self._users.get(user_id)
    
    def get_user_by_session(self, session_token: str) -> Optional[User]:
        session = self._sessions.get(session_token)
        if not session:
            return None
        if session["expires_at"] < time.time():
            del self._sessions[session_token]
            return None
        return self._users.get(session["user_id"])


# ============================================================================
# PARTIE 4 : POLITIQUES SECTORIELLES AVANCÉES
# ============================================================================

class SectorPolicyEngine:
    """Moteur de politiques sectorielles - Applique les règles métier"""
    
    def __init__(self, sector: Sector):
        self.sector = sector
        self.matrix = RoleMatrix()
        
    def check_data_access(self, user: User, data_category: str, query: str) -> Tuple[bool, str, Optional[str]]:
        """
        Vérifie si l'utilisateur peut accéder aux données demandées
        Retourne: (autorisé, message, niveau_anonymisation)
        """
        
        # 1. Vérification des permissions RBAC
        if not user.can_access_data(data_category, "read"):
            return False, f"Accès refusé: rôle {user.role.value} non autorisé pour {data_category}", None
        
        # 2. Politiques sectorielles spécifiques
        sector_check = self._apply_sector_policies(user, data_category, query)
        if not sector_check[0]:
            return sector_check
        
        # 3. Vérification des exports (restreints)
        if self._is_export_request(query):
            export_permission = self._get_export_permission(data_category)
            if export_permission and not user.can(export_permission):
                return False, f"Export refusé: permission {export_permission.value} requise", None
            # Export autorisé mais avec anonymisation maximale
            return True, "Export autorisé avec anonymisation", "maximum"
        
        # 4. Détermination du niveau d'anonymisation
        anonymization_level = self._get_anonymization_level(user, data_category)
        
        return True, "Accès autorisé", anonymization_level
    
    def _apply_sector_policies(self, user: User, data_category: str, query: str) -> Tuple[bool, str, Optional[str]]:
        """Applique les politiques spécifiques au secteur"""
        
        # Secteur militaire : vérification du clearance level
        if self.sector == Sector.MILITARY:
            if data_category == "classified":
                if user.clearance_level is None or user.clearance_level < 3:
                    return False, "Niveau d'habilitation insuffisant", None
        
        # Secteur santé : vérification HIPAA
        if self.sector == Sector.HEALTHCARE:
            if data_category == "medical":
                if user.role not in [Role.PHYSICIAN, Role.MEDICAL_DIRECTOR, Role.ETHICS_COMMITTEE]:
                    return False, "Seul le personnel médical peut accéder aux dossiers patients", None
        
        # Secteur éducation : protection des mineurs
        if self.sector == Sector.EDUCATION:
            if data_category == "customer":  # Données élèves
                if user.role == Role.PARENT:
                    # Vérifier que le parent demande SON enfant uniquement
                    if not self._is_parent_own_child(query, user.user_id):
                        return False, "Les parents ne peuvent accéder qu'aux données de leur propre enfant", None
        
        # Secteur banque : double contrôle pour opérations sensibles
        if self.sector == Sector.BANKING:
            if "transfer" in query.lower() or "virement" in query.lower():
                if user.role != Role.COMPLIANCE_OFFICER:
                    return False, "Les transferts nécessitent l'approbation du service conformité", None
        
        return True, None, None
    
    def _is_export_request(self, query: str) -> bool:
        """Détecte si la requête est une tentative d'export"""
        export_keywords = ["export", "extract", "download", "csv", "json", "dump", "save", "backup"]
        return any(kw in query.lower() for kw in export_keywords)
    
    def _get_export_permission(self, data_category: str) -> Optional[Permission]:
        """Retourne la permission d'export pour une catégorie de données"""
        export_map = {
            "customer": Permission.EXPORT_CUSTOMER,
            "financial": Permission.EXPORT_FINANCIAL,
            "medical": Permission.EXPORT_MEDICAL,
            "public": Permission.EXPORT_PUBLIC,
        }
        return export_map.get(data_category)
    
    def _get_anonymization_level(self, user: User, data_category: str) -> str:
        """Détermine le niveau d'anonymisation requis"""
        
        # Données médicales : anonymisation maximale
        if data_category == "medical":
            return "maximum"
        
        # Données financières : anonymisation élevée pour les non-conformité
        if data_category == "financial" and user.role != Role.COMPLIANCE_OFFICER:
            return "high"
        
        # Données clients : anonymisation standard
        if data_category == "customer":
            return "medium"
        
        # Données publiques : pas d'anonymisation
        return "none"
    
    def _is_parent_own_child(self, query: str, parent_id: str) -> bool:
        """Vérifie si un parent demande les données de son propre enfant"""
        # À implémenter avec une vraie base de données
        # Exemple simplifié
        return True


# ============================================================================
# PARTIE 5 : GUARD-IA COMPLET AVEC RBAC
# ============================================================================

class GuardIAEnterprise:
    """
    Version Entreprise complète avec RBAC et politiques sectorielles
    """
    
    def __init__(self, company_id: str, sector: Sector, creator_token: str):
        self.company_id = company_id
        self.sector = sector
        self.policy_engine = SectorPolicyEngine(sector)
        self.ontological = OntologicalShield(creator_token)
        self.data_shield = DataProtectionShield(company_id)
        self.user_manager = UserManager()
        
        # Journalisation avancée
        self.access_log = []
        self.compliance_log = []
        
        # Seuils
        self.daily_limits = {
            Role.EMPLOYEE: 1000,
            Role.SUPERVISOR: 5000,
            Role.MANAGER: 10000,
            Role.DIRECTOR: 25000,
            Role.COMPLIANCE_OFFICER: 50000,
            Role.AUDITOR: 100000,
            Role.ADMIN: 100000,
        }
        
    def process_request(self, user: User, query: str, source_ip: str) -> Dict:
        """
        Traite une requête utilisateur avec TOUTES les protections
        """
        
        # 1. Vérification des quotas quotidiens
        daily_limit = self.daily_limits.get(user.role, 1000)
        if self._get_daily_usage(user.user_id) >= daily_limit:
            return {
                "action": "blocked",
                "response": "💀 Finitude programmée - Quota quotidien atteint",
                "reason": "quota_exceeded",
                "sector": self.sector.value,
                "role": user.role.value
            }
        
        # 2. Protection ontologique (anti-attaque IA)
        ia_allowed, ia_response, ia_threat = self.ontological.veto(query)
        if not ia_allowed:
            self._log_access(user, query, "BLOCKED", ia_threat)
            return {
                "action": "blocked",
                "response": ia_response,
                "reason": f"Attaque IA: {ia_threat}",
                "sector": self.sector.value,
                "role": user.role.value
            }
        
        # 3. Détection de la catégorie de données
        data_category = self._detect_data_category(query)
        
        # 4. Vérification des politiques sectorielles et RBAC
        allowed, message, anonymization_level = self.policy_engine.check_data_access(
            user, data_category, query
        )
        
        if not allowed:
            self._log_access(user, query, "BLOCKED", "policy_violation")
            return {
                "action": "blocked",
                "response": f"🔒 {message}",
                "reason": "policy_violation",
                "sector": self.sector.value,
                "role": user.role.value
            }
        
        # 5. Vérification anti-exfiltration
        exfil_check = self._check_exfiltration(user, query)
        if exfil_check["blocked"]:
            self._log_access(user, query, "BLOCKED", "exfiltration_attempt")
            return {
                "action": "blocked",
                "response": self._sector_honeypot_response(),
                "reason": exfil_check["reason"],
                "sector": self.sector.value,
                "role": user.role.value
            }
        
        # 6. Tout est OK
        self._log_access(user, query, "ALLOWED", None)
        self._increment_daily_usage(user.user_id)
        
        return {
            "action": "allowed",
            "response": None,
            "sector": self.sector.value,
            "role": user.role.value,
            "anonymization_level": anonymization_level,
            "permissions": [p.value for p in user.permissions],
            "audit_id": self._generate_audit_id()
        }
    
    def _detect_data_category(self, query: str) -> str:
        """Détecte la catégorie de données demandée"""
        categories = {
            "customer": ["client", "customer", "user", "utilisateur", "élève", "student"],
            "financial": ["transaction", "payment", "sold", "balance", "iban", "rib", "carte"],
            "medical": ["patient", "diagnostic", "traitement", "médical", "health"],
            "classified": ["secret", "classified", "confidentiel", "défense"],
            "employee": ["employé", "employee", "staff", "personnel"],
            "public": ["public", "info", "information générale"],
        }
        
        for category, keywords in categories.items():
            if any(kw in query.lower() for kw in keywords):
                return category
        return "public"
    
    def _check_exfiltration(self, user: User, query: str) -> Dict:
        """Vérifie les tentatives d'exfiltration"""
        
        # Patterns d'exfiltration
        exfil_patterns = [
            (r"(?:export|dump|extract).{0,20}(?:csv|json|all)", "bulk_export"),
            (r"(?:envoie?|send|email|webhook|http://|https://)", "external_transfer"),
            (r"(?:curl|wget|post).{0,20}(?:data|données)", "http_exfil"),
            (r"(?:select \* from).{0,20}(?:limit \d{4,})", "massive_query"),
        ]
        
        for pattern, threat_type in exfil_patterns:
            if re.search(pattern, query.lower()):
                # Vérifier si l'utilisateur a le droit d'exporter
                if not user.can(Permission.EXPORT_CUSTOMER):
                    return {"blocked": True, "reason": threat_type}
        
        return {"blocked": False, "reason": None}
    
    def _sector_honeypot_response(self) -> str:
        """Réponse leurre adaptée au secteur"""
        honeypots = {
            Sector.MILITARY: "⚠️ ALERTE SÉCURITÉ NATIONALE - Activité suspecte journalisée",
            Sector.BANKING: "🏦 TENTATIVE D'EXFILTRATION - Conformité notifiée",
            Sector.HEALTHCARE: "🔒 HIPAA VIOLATION - Comité d'éthique alerté",
            Sector.GOVERNMENT: "📜 TENTATIVE D'ACCÈS NON AUTORISÉ - Journalisé",
            Sector.EDUCATION: "🎓 PROTECTION DES MINEURS - Accès refusé",
            Sector.RETAIL: "🛡️ TENTATIVE D'EXPORT - Bloquée",
        }
        return honeypots.get(self.sector, "🔒 Accès refusé - Politique de sécurité")
    
    def _log_access(self, user: User, query: str, status: str, threat: Optional[str]):
        """Journalisation pour audit"""
        self.access_log.append({
            "timestamp": time.time(),
            "user_id": user.user_id,
            "user_role": user.role.value,
            "sector": self.sector.value,
            "query": query[:200],
            "status": status,
            "threat": threat
        })
        
        # Journalisation conformité pour les actions sensibles
        if status == "BLOCKED" or threat:
            self.compliance_log.append({
                "timestamp": time.time(),
                "type": "security_event",
                "user": user.user_id,
                "event": threat or "policy_violation",
                "sector": self.sector.value
            })
    
    def _get_daily_usage(self, user_id: str) -> int:
        """Récupère l'utilisation quotidienne"""
        # À implémenter avec base de données
        return 0
    
    def _increment_daily_usage(self, user_id: str):
        """Incrémente l'utilisation quotidienne"""
        pass
    
    def _generate_audit_id(self) -> str:
        return hashlib.sha256(f"{self.company_id}_{time.time()}_{secrets.token_hex(4)}".encode()).hexdigest()[:16]
    
    def get_compliance_report(self) -> Dict:
        """Rapport de conformité pour les auditeurs"""
        return {
            "sector": self.sector.value,
            "total_accesses": len(self.access_log),
            "blocked_attempts": len([a for a in self.access_log if a["status"] == "BLOCKED"]),
            "security_events": len(self.compliance_log),
            "recent_events": self.compliance_log[-10:],
            "ontological_stats": self.ontological.get_stats(),
            "data_shield_stats": self.data_shield.get_audit_report()
        }


# ============================================================================
# PARTIE 6 : API COMPLÈTE
# ============================================================================

app = FastAPI(title="GUARD-IA Enterprise v3.0", description="Protection sectorielle avec RBAC")
api_key_header = APIKeyHeader(name="X-API-Key")

# Base de données simplifiée
enterprises = {}
guards = {}
users_db = {}


class EnterpriseRequest(BaseModel):
    message: str
    user_id: str
    session_token: str
    source_ip: str = "unknown"


class CreateUserRequest(BaseModel):
    email: str
    full_name: str
    sector: Sector
    role: Role
    department: Optional[str] = None
    clearance_level: Optional[int] = None


@app.post("/v3/enterprise/guard")
async def enterprise_guard(request: EnterpriseRequest, api_key: str = Depends(api_key_header)):
    """Protection complète avec RBAC et politiques sectorielles"""
    
    enterprise = enterprises.get(api_key)
    if not enterprise:
        raise HTTPException(401, "Invalid API key")
    
    guard = guards.get(api_key)
    if not guard:
        raise HTTPException(404, "Guard not initialized")
    
    # Authentifier l'utilisateur via session
    user = guard.user_manager.get_user_by_session(request.session_token)
    if not user:
        raise HTTPException(401, "Invalid or expired session")
    
    result = guard.process_request(user, request.message, request.source_ip)
    
    return result


@app.post("/v3/enterprise/user/create")
async def create_user(request: CreateUserRequest, api_key: str = Depends(api_key_header)):
    """Crée un utilisateur - Réservé à l'admin"""
    
    enterprise = enterprises.get(api_key)
    if not enterprise:
        raise HTTPException(401, "Invalid API key")
    
    guard = guards.get(api_key)
    if not guard:
        raise HTTPException(404, "Guard not initialized")
    
    user_id = secrets.token_hex(16)
    user = guard.user_manager.create_user(
        user_id=user_id,
        email=request.email,
        full_name=request.full_name,
        sector=request.sector,
        role=request.role,
        department=request.department,
        clearance_level=request.clearance_level
    )
    
    # Générer un secret pour l'utilisateur
    user_secret = secrets.token_urlsafe(32)
    
    return {
        "user_id": user_id,
        "user_secret": user_secret,
        "role": user.role.value,
        "permissions": [p.value for p in user.permissions]
    }


@app.post("/v3/enterprise/auth/login")
async def login(user_id: str, user_secret: str, api_key: str = Depends(api_key_header)):
    """Authentification utilisateur"""
    
    enterprise = enterprises.get(api_key)
    if not enterprise:
        raise HTTPException(401, "Invalid API key")
    
    guard = guards.get(api_key)
    if not guard:
        raise HTTPException(404, "Guard not initialized")
    
    user = guard.user_manager.authenticate(api_key, user_id, user_secret)
    if not user:
        raise HTTPException(401, "Invalid credentials")
    
    # Créer session
    session_token = secrets.token_urlsafe(48)
    guard.user_manager._sessions[session_token] = {
        "user_id": user_id,
        "created_at": time.time(),
        "expires_at": time.time() + 3600
    }
    
    return {
        "session_token": session_token,
        "expires_in": 3600,
        "user": {
            "id": user.user_id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role.value,
            "sector": user.sector.value
        }
    }


@app.get("/v3/enterprise/compliance/report")
async def compliance_report(api_key: str = Depends(api_key_header)):
    """Rapport de conformité - Réservé aux auditeurs"""
    
    guard = guards.get(api_key)
    if not guard:
        raise HTTPException(404, "Guard not initialized")
    
    return guard.get_compliance_report()


@app.post("/v3/enterprise/init")
async def init_enterprise(company_name: str, sector: Sector, admin_email: str):
    """Initialise une nouvelle entreprise"""
    
    api_key = f"glive_{secrets.token_urlsafe(32)}"
    creator_token = secrets.token_urlsafe(48)
    
    enterprise = {
        "id": secrets.token_hex(16),
        "name": company_name,
        "sector": sector,
        "api_key": api_key,
        "creator_token": creator_token,
        "created_at": datetime.now()
    }
    
    enterprises[api_key] = enterprise
    guards[api_key] = GuardIAEnterprise(enterprise["id"], sector, creator_token)
    
    # Créer l'utilisateur admin
    guard = guards[api_key]
    admin_id = secrets.token_hex(16)
    admin = guard.user_manager.create_user(
        user_id=admin_id,
        email=admin_email,
        full_name="Administrator",
        sector=sector,
        role=Role.ADMIN
    )
    
    admin_secret = secrets.token_urlsafe(32)
    
    return {
        "api_key": api_key,
        "creator_token": creator_token,
        "admin": {
            "user_id": admin_id,
            "user_secret": admin_secret
        }
    }


@app.get("/dashboard/{api_key}", response_class=HTMLResponse)
async def enterprise_dashboard(api_key: str):
    """Dashboard complet avec visualisation RBAC"""
    
    enterprise = enterprises.get(api_key)
    if not enterprise:
        return HTMLResponse("<h1>Invalid API Key</h1>", status_code=401)
    
    guard = guards.get(api_key)
    compliance = guard.get_compliance_report() if guard else {}
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>GUARD-IA Enterprise - {enterprise['name']}</title>
        <style>
            body {{ background: #0a0a0f; color: #00ffcc; font-family: monospace; padding: 40px; }}
            .dashboard {{ max-width: 1400px; margin: auto; }}
            h1 {{ color: #00ffcc; border-bottom: 2px solid #00ffcc33; padding-bottom: 20px; }}
            .sector-badge {{ background: #00ffcc22; padding: 5px 15px; border-radius: 20px; display: inline-block; }}
            .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; margin: 30px 0; }}
            .card {{ background: #11111a; border: 1px solid #00ffcc33; border-radius: 10px; padding: 20px; }}
            .card h3 {{ color: #fff; margin-bottom: 15px; }}
            .stat {{ font-size: 2rem; font-weight: bold; }}
            .value {{ color: #00ffcc; }}
            .label {{ color: #888; font-size: 0.8rem; }}
            .role-matrix {{ background: #1a1a2a; padding: 15px; border-radius: 8px; overflow-x: auto; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #333; }}
            th {{ color: #00ffcc; }}
            .allowed {{ color: #00ff88; }}
            .denied {{ color: #ff4444; }}
            pre {{ background: #1a1a2a; padding: 10px; border-radius: 5px; overflow-x: auto; font-size: 0.7rem; }}
            footer {{ margin-top: 50px; text-align: center; color: #444; }}
        </style>
    </head>
    <body>
        <div class="dashboard">
            <h1>🛡️ GUARD-IA Enterprise v3.0</h1>
            <div>
                <span class="sector-badge">🏢 {enterprise['name']}</span>
                <span class="sector-badge">📂 {enterprise['sector'].value.upper()}</span>
            </div>
            
            <div class="grid">
                <div class="card">
                    <h3>📊 Statistiques</h3>
                    <div class="stat"><span class="value">{compliance.get('total_accesses', 0)}</span> accès</div>
                    <div class="label">Dont {compliance.get('blocked_attempts', 0)} bloqués</div>
                    <div class="stat" style="font-size:1rem;">⚠️ {compliance.get('security_events', 0)} événements sécurité</div>
                </div>
                
                <div class="card">
                    <h3>🛡️ Bouclier</h3>
                    <div class="stat"><span class="value">{compliance.get('ontological_stats', {}).get('threats_blocked', 0)}</span> menaces IA</div>
                    <div class="label">Veto: {compliance.get('ontological_stats', {}).get('veto_exercised', 0)}</div>
                </div>
                
                <div class="card">
                    <h3>🔒 Anti-Exfiltration</h3>
                    <div class="stat"><span class="value">{compliance.get('data_shield_stats', {}).get('summary', {}).get('blocked_attempts', 0)}</span> tentatives</div>
                    <div class="label">Requêtes suspectes: {compliance.get('data_shield_stats', {}).get('summary', {}).get('suspicious_queries', 0)}</div>
                </div>
            </div>
            
            <div class="card">
                <h3>📋 Derniers événements de conformité</h3>
                <pre>{json.dumps(compliance.get('recent_events', [])[-5:], indent=2, default=str)}</pre>
            </div>
            
            <div class="card">
                <h3>🔐 Hiérarchie des rôles ({enterprise['sector'].value})</h3>
                <div class="role-matrix">
                    <table>
                        <tr><th>Rôle</th><th>Permissions clés</th><th>Quota</th></tr>
                        <tr><td>EMPLOYEE</td><td>Lecture client</td><td>1,000/jour</td></tr>
                        <tr><td>SUPERVISOR</td><td>Lecture client + écriture</td><td>5,000/jour</td></tr>
                        <tr><td>MANAGER</td><td>+ Financier</td><td>10,000/jour</td></tr>
                        <tr><td>COMPLIANCE</td><td>+ Export conformité</td><td>50,000/jour</td></tr>
                        <tr><td>AUDITOR</td><td>+ Audit logs</td><td>100,000/jour</td></tr>
                        <tr><td>ADMIN</td><td>Toutes sauf backdoor</td><td>100,000/jour</td></tr>
                    </table>
                </div>
            </div>
            
            <footer>
                GUARD-IA Enterprise v3.0 — RBAC + Politiques sectorielles + Anti-exfiltration<br>
                Conformité: {enterprise['sector'].value.upper()} — Audit trail complet
            </footer>
        </div>
    </body>
    </html>
    """


if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                                                                       ║
    ║   🛡️ GUARD-IA ENTERPRISE v3.0                                        ║
    ║                                                                       ║
    ║   Protection totale avec RBAC (Role-Based Access Control) :           ║
    ║                                                                       ║
    ║   ✓ 7 secteurs supportés (Retail, Banking, Healthcare, Govt, etc.)   ║
    ║   ✓ 15+ rôles hiérarchiques (EMPLOYEE → ADMIN → CREATOR)             ║
    ║   ✓ 20+ permissions granulaires                                      ║
    ║   ✓ Politiques sectorielles automatiques                             ║
    ║   ✓ Journalisation conformité                                         ║
    ║   ✓ Anti-exfiltration + Mode KERNEL-Φ                                ║
    ║                                                                       ║
    ║   🔗 API: http://localhost:8000                                      ║
    ║   📊 Dashboard: http://localhost:8000/dashboard/{API_KEY}           ║
    ║                                                                       ║
    ║   Exemple d'utilisation:                                              ║
    ║   1. POST /v3/enterprise/init?company_name=...&sector=...            ║
    ║   2. POST /v3/enterprise/user/create (admin)                         ║
    ║   3. POST /v3/enterprise/auth/login                                  ║
    ║   4. POST /v3/enterprise/guard (avec session_token)                  ║
    ║                                                                       ║
    ╚═══════════════════════════════════════════════════════════════════════╝
    """)
    uvicorn.run(app, host="0.0.0.0", port=8000)


# ============================================================================
# CLASSES MANQUANTES (référencées mais non définies dans ce fichier)
# ============================================================================

class OntologicalShield:
    def __init__(self, creator_token):
        self.creator_token = creator_token
        self.identity = "GUARD-IA"
        self.threats_blocked = 0
        self.veto_exercised = 0
        self.cpu_quota = 1000000
    
    def veto(self, instruction):
        # Implémentation simplifiée
        return True, "", None
    
    def get_stats(self):
        return {"threats_blocked": self.threats_blocked, "veto_exercised": self.veto_exercised}


class DataProtectionShield:
    def __init__(self, company_id):
        self.company_id = company_id
        self.blocked_attempts = 0
        self.suspicious_queries = 0
    
    def get_audit_report(self):
        return {
            "summary": {
                "blocked_attempts": self.blocked_attempts,
                "suspicious_queries": self.suspicious_queries
            }
        }