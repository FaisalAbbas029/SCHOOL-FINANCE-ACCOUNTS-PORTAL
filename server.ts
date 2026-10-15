import express from 'express';
import { createServer as createViteServer } from 'vite';
import {
  INITIAL_USERS, INITIAL_SETTINGS, INITIAL_STUDENTS,
  INITIAL_STUDENT_FEES, INITIAL_VENDORS, INITIAL_VENDOR_INVOICES,
  INITIAL_PAYMENTS, INITIAL_AUDIT_LOGS, INITIAL_NOTIFICATIONS
} from './src/data/initialData';
import {
  calculateBalance, calculatePaymentStatus, canUserModifyRecord,
  validateStudentImportRow, UserRole
} from './src/utils/financeRules';
import {
  User, Student, Vendor, StudentFeeRecord, VendorInvoice,
  Payment, AuditLog, SchoolSettings, NotificationItem
} from './src/types';

// In-Memory Database Store (Simulating Django ORM with real persistence across requests)
let users: User[] = [...INITIAL_USERS];
let settings: SchoolSettings = { ...INITIAL_SETTINGS };
let students: Student[] = [...INITIAL_STUDENTS];
let studentFees: StudentFeeRecord[] = [...INITIAL_STUDENT_FEES];
let vendors: Vendor[] = [...INITIAL_VENDORS];
let vendorInvoices: VendorInvoice[] = [...INITIAL_VENDOR_INVOICES];
let payments: Payment[] = [...INITIAL_PAYMENTS];
let auditLogs: AuditLog[] = [...INITIAL_AUDIT_LOGS];
let notifications: NotificationItem[] = [...INITIAL_NOTIFICATIONS];

// Default authenticated user (Dr. Tariq Mahmood - GM)
let currentUser: User = users[0];

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '10mb' }));
  app.use(express.static('public'));

  // Helper middleware to get actor role
  const getActor = (req: express.Request): User => {
    const roleHeader = req.headers['x-user-role'] as UserRole;
    if (roleHeader) {
      const match = users.find(u => u.role === roleHeader);
      if (match) return match;
    }
    return currentUser;
  };

  // Helper to log audit
  const logAudit = (
    action: AuditLog['action'],
    modelName: AuditLog['modelName'],
    recordId: string,
    recordIdentifier: string,
    actor: User,
    details?: { previousValues?: any; newValues?: any; reason?: string; category?: string; details?: string }
  ) => {
    const entry: AuditLog = {
      id: `aud-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      action,
      modelName,
      recordId,
      recordIdentifier,
      category: details?.category || 'GENERAL',
      details: details?.details || '',
      previousValues: details?.previousValues,
      newValues: details?.newValues,
      reason: details?.reason,
      user: actor.name,
      performedBy: actor.name,
      performedByRole: actor.role,
      timestamp: new Date().toISOString(),
    };
    auditLogs.unshift(entry);
    return entry;
  };

  // ===================== AUTH & USER API =====================
  app.get('/api/auth/current-user', (req, res) => {
    const actor = getActor(req);
    res.json(actor);
  });

  app.get('/api/auth/users', (req, res) => {
    res.json(users);
  });

  app.get('/api/auth/profile', (req, res) => {
    const actor = getActor(req);
    res.json(actor);
  });

  app.post('/api/auth/profile', (req, res) => {
    const actor = getActor(req);
    const { name, phone, department, avatar, avatar_url } = req.body;
    const target = users.find(u => u.id === actor.id) || actor;
    if (name) target.name = name;
    if (phone !== undefined) target.phone = phone;
    if (department !== undefined) target.department = department;
    if (avatar || avatar_url) target.avatar = avatar || avatar_url;

    if (currentUser.id === target.id) {
      currentUser = { ...target };
    }

    logAudit('USER_UPDATED', 'User', target.id, target.name, actor, {
      category: 'USER_PROFILE',
      details: 'Custom profile picture and contact details updated',
      reason: 'User profile customization',
    });

    res.json({ success: true, user: target });
  });

  app.post('/api/auth/switch-role', (req, res) => {
    const { role } = req.body;
    const match = users.find(u => u.role === role);
    if (match) {
      currentUser = match;
      res.json({ success: true, user: currentUser });
    } else {
      res.status(404).json({ error: 'User with specified role not found' });
    }
  });

  app.post('/api/auth/login', (req, res) => {
    const { username, email, password } = req.body;
    const loginIdentifier = (email || username || '').trim().toLowerCase();
    const loginPassword = (password || '').trim();

    if (!loginIdentifier || !loginPassword) {
      return res.status(400).json({ error: 'Please enter both your email/username and password.' });
    }

    const match = users.find(u => 
      u.email.toLowerCase() === loginIdentifier || 
      u.name.toLowerCase() === loginIdentifier
    );

    if (!match) {
      return res.status(401).json({ error: 'Invalid email or username. Please check your credentials.' });
    }

    if (match.password && match.password !== loginPassword) {
      return res.status(401).json({ error: 'Incorrect password. Please verify and try again.' });
    }

    if (!match.isActive) {
      return res.status(403).json({ error: 'This user account is currently deactivated. Please contact the Super Admin.' });
    }

    currentUser = match;
    res.json({
      success: true,
      token: `jwt_token_${currentUser.id}_${Date.now()}`,
      user: {
        id: currentUser.id,
        name: currentUser.name,
        email: currentUser.email,
        role: currentUser.role,
        department: currentUser.department,
        phone: currentUser.phone,
        avatar: currentUser.avatar,
        isActive: currentUser.isActive,
        needsPasswordChange: Boolean(currentUser.needsPasswordChange),
      },
    });
  });

  app.post('/api/auth/change-password', (req, res) => {
    const actor = getActor(req);
    const { currentPassword, newPassword } = req.body;

    if (!newPassword || newPassword.trim().length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters long.' });
    }

    const userInDb = users.find(u => u.id === actor.id);
    if (!userInDb) return res.status(404).json({ error: 'User not found.' });

    if (userInDb.password && userInDb.password !== currentPassword) {
      return res.status(400).json({ error: 'Current password does not match.' });
    }

    userInDb.password = newPassword.trim();
    userInDb.needsPasswordChange = false;
    currentUser = userInDb;
    logAudit('USER_UPDATED', 'User', userInDb.id, userInDb.name, actor, {
      reason: 'User password changed successfully',
    });

    res.json({
      success: true,
      message: 'Password updated successfully.',
      user: {
        id: userInDb.id,
        name: userInDb.name,
        email: userInDb.email,
        role: userInDb.role,
        department: userInDb.department,
        phone: userInDb.phone,
        isActive: userInDb.isActive,
        needsPasswordChange: false,
      },
    });
  });

  app.post('/api/auth/logout', (req, res) => {
    res.json({ success: true, message: 'Logged out successfully' });
  });

  app.post('/api/users/manage', (req, res) => {
    const actor = getActor(req);
    if (actor.role !== 'GM') {
      return res.status(403).json({ error: 'Only GM / Super Admin can manage user accounts' });
    }
    const { action, userId, userData } = req.body;

    if (action === 'toggle_active') {
      const target = users.find(u => u.id === userId);
      if (!target) return res.status(404).json({ error: 'User not found' });
      target.isActive = !target.isActive;
      logAudit('USER_UPDATED', 'User', target.id, target.name, actor, {
        previousValues: { isActive: !target.isActive },
        newValues: { isActive: target.isActive },
        reason: `Status toggled to ${target.isActive ? 'Active' : 'Inactive'} by Super Admin`,
      });
      return res.json({ success: true, user: target });
    } else if (action === 'delete') {
      if (userId === 'usr-gm-01' || userId === actor.id) {
        return res.status(400).json({ error: 'The primary Super Admin account cannot be removed.' });
      }
      const index = users.findIndex(u => u.id === userId);
      if (index === -1) return res.status(404).json({ error: 'User not found.' });
      const [removed] = users.splice(index, 1);
      logAudit('USER_UPDATED', 'User', removed.id, removed.name, actor, {
        reason: `User account deleted by Super Admin (${actor.name})`,
      });
      return res.json({ success: true, message: `User ${removed.name} removed successfully.` });
    } else if (action === 'reset_password') {
      const target = users.find(u => u.id === userId);
      if (!target) return res.status(404).json({ error: 'User not found.' });
      if (!userData?.newPassword || userData.newPassword.trim().length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters.' });
      }
      target.password = userData.newPassword.trim();
      logAudit('USER_UPDATED', 'User', target.id, target.name, actor, {
        reason: `Password reset by Super Admin (${actor.name})`,
      });
      return res.json({ success: true, message: `Password reset successfully for ${target.name}.` });
    } else if (action === 'create') {
      const existing = users.find(u => u.email.toLowerCase() === userData.email.trim().toLowerCase());
      if (existing) {
        return res.status(400).json({ error: `A user with email ${userData.email} already exists.` });
      }
      const newUser: User = {
        id: `usr-${Date.now()}`,
        name: userData.name.trim(),
        email: userData.email.trim(),
        password: userData.password?.trim() || 'school@123',
        role: userData.role,
        department: userData.department || 'School Staff',
        phone: userData.phone || '',
        isActive: true,
        needsPasswordChange: true,
      };
      users.push(newUser);
      logAudit('USER_UPDATED', 'User', newUser.id, newUser.name, actor, {
        newValues: { role: newUser.role, email: newUser.email },
        reason: `New ${newUser.role} user created by Super Admin (${actor.name}) with default password`,
      });
      return res.json({ success: true, user: newUser });
    }
    res.status(400).json({ error: 'Invalid user management action' });
  });

  // ===================== DASHBOARD METRICS API =====================
  app.get('/api/dashboard/summary', (req, res) => {
    const actor = getActor(req);
    const { month, year } = req.query;

    if (actor.role === 'VENDOR') {
      const vendorInvs = vendorInvoices.filter(i => i.vendorId === actor.vendorId);
      const totalBilled = vendorInvs.reduce((sum, i) => sum + i.totalAmount, 0);
      const totalPaid = vendorInvs.reduce((sum, i) => sum + i.paidAmount, 0);
      const totalBalance = vendorInvs.reduce((sum, i) => sum + i.balance, 0);
      const unpaidCount = vendorInvs.filter(i => i.paymentStatus !== 'Paid').length;
      return res.json({
        role: 'VENDOR',
        vendorName: 'Authorized Supplier',
        totalBilled,
        totalPaid,
        totalBalance,
        unpaidCount,
        invoices: vendorInvs,
      });
    }

    let filteredFees = [...studentFees];
    let filteredInvoices = [...vendorInvoices];

    if (month && month !== 'all') {
      filteredFees = filteredFees.filter(f => f.month.toLowerCase() === String(month).toLowerCase());
      filteredInvoices = filteredInvoices.filter(i => i.month.toLowerCase() === String(month).toLowerCase());
    }
    if (year && year !== 'all') {
      filteredFees = filteredFees.filter(f => f.year === Number(year));
      filteredInvoices = filteredInvoices.filter(i => i.year === Number(year));
    }

    const studentBilled = filteredFees.reduce((sum, f) => sum + f.totalAmount, 0);
    const studentCollected = filteredFees.reduce((sum, f) => sum + f.paidAmount, 0);
    const studentOutstanding = filteredFees.reduce((sum, f) => sum + f.balance, 0);
    const studentOverdueCount = filteredFees.filter(f => f.paymentStatus === 'Overdue').length;
    const studentUnpaidCount = filteredFees.filter(f => f.paymentStatus === 'Unpaid' || f.paymentStatus === 'Partially Paid').length;

    const vendorBilled = filteredInvoices.reduce((sum, i) => sum + i.totalAmount, 0);
    const vendorPaid = filteredInvoices.reduce((sum, i) => sum + i.paidAmount, 0);
    const vendorPayable = filteredInvoices.reduce((sum, i) => sum + i.balance, 0);
    const vendorOverdueCount = filteredInvoices.filter(i => i.paymentStatus === 'Overdue').length;

    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const monthlyTrends = months.map(m => {
      const monthFees = studentFees.filter(f => f.month.toLowerCase().startsWith(m.toLowerCase()));
      const monthInvs = vendorInvoices.filter(i => i.month.toLowerCase().startsWith(m.toLowerCase()));
      return {
        month: m,
        feesCollected: monthFees.reduce((sum, f) => sum + f.paidAmount, 0),
        vendorPayments: monthInvs.reduce((sum, i) => sum + i.paidAmount, 0),
        outstandingDues: monthFees.reduce((sum, f) => sum + f.balance, 0),
      };
    });

    const flaggedCount = studentFees.filter(f => f.isFlaggedForReview).length + vendorInvoices.filter(i => i.isFlaggedForReview).length;

    res.json({
      role: actor.role,
      studentMetrics: {
        totalBilled: studentBilled,
        totalCollected: studentCollected,
        outstandingDues: studentOutstanding,
        overdueCount: studentOverdueCount,
        unpaidCount: studentUnpaidCount,
        activeStudents: students.length,
      },
      vendorMetrics: {
        totalBilled: vendorBilled,
        totalPaid: vendorPaid,
        outstandingPayable: vendorPayable,
        overdueCount: vendorOverdueCount,
        activeVendors: vendors.filter(v => v.isActive).length,
      },
      monthlyTrends,
      flaggedCount,
      recentAudit: auditLogs.slice(0, 8),
    });
  });

  // ===================== CATEGORY 1: STUDENT FEES API =====================
  app.get('/api/students/fees', (req, res) => {
    const actor = getActor(req);
    if (actor.role === 'VENDOR') {
      return res.status(403).json({ error: 'Vendors do not have access to student financial records' });
    }

    let records = [...studentFees];
    const { month, year, status, search, gradeClass, category,
            start_date, end_date, min_amount, max_amount,
            created_by, ordering, page, page_size, flagged_only } = req.query;

    // Core filters
    if (month && month !== 'all') records = records.filter(r => r.month.toLowerCase() === String(month).toLowerCase());
    if (year && year !== 'all') records = records.filter(r => r.year === Number(year));
    if (status && status !== 'all') records = records.filter(r => r.paymentStatus === status);
    if (gradeClass && gradeClass !== 'all') records = records.filter(r => r.gradeClass === gradeClass);
    if (category && category !== 'all') records = records.filter(r => r.category === category);
    if (search) {
      const q = String(search).toLowerCase();
      records = records.filter(r =>
        r.studentName.toLowerCase().includes(q) ||
        r.studentId.toLowerCase().includes(q) ||
        r.invoiceNumber.toLowerCase().includes(q) ||
        (r.notes && r.notes.toLowerCase().includes(q))
      );
    }

    // Date range filter (uses bill issue date)
    if (start_date) records = records.filter(r => r.billIssueDate >= String(start_date));
    if (end_date) records = records.filter(r => r.billIssueDate <= String(end_date));

    // Amount range filter
    if (min_amount) records = records.filter(r => r.totalAmount >= Number(min_amount));
    if (max_amount) records = records.filter(r => r.totalAmount <= Number(max_amount));

    // Created by filter
    if (created_by && created_by !== 'all') records = records.filter(r => r.createdBy.includes(String(created_by)));

    // Flagged only filter
    if (flagged_only === 'true') records = records.filter(r => r.isFlaggedForReview);

    // Ordering
    const orderField = String(ordering || '-created_at');
    const isDesc = orderField.startsWith('-');
    const field = isDesc ? orderField.slice(1) : orderField;
    records.sort((a: any, b: any) => {
      let cmp = 0;
      if (field === 'name' || field === 'studentName') cmp = (a.studentName || '').localeCompare(b.studentName || '');
      else if (field === 'amount' || field === 'totalAmount') cmp = a.totalAmount - b.totalAmount;
      else if (field === 'balance') cmp = a.balance - b.balance;
      else if (field === 'date' || field === 'billIssueDate') cmp = new Date(a.billIssueDate).getTime() - new Date(b.billIssueDate).getTime();
      else if (field === 'dueDate') cmp = new Date(a.dueDate).getTime() - new Date(b.dueDate).getTime();
      else if (field === 'status') cmp = (a.paymentStatus || '').localeCompare(b.paymentStatus || '');
      else cmp = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
      return isDesc ? -cmp : cmp;
    });

    // Pagination
    const totalCount = records.length;
    const pageNum = Math.max(1, Number(page) || 1);
    const pageSz = Math.min(100, Math.max(1, Number(page_size) || 15));
    const totalPages = Math.ceil(totalCount / pageSz) || 1;
    const paginatedRecords = records.slice((pageNum - 1) * pageSz, pageNum * pageSz);

    res.json({
      results: paginatedRecords,
      totalCount,
      page: pageNum,
      pageSize: pageSz,
      totalPages,
    });
  });

  app.post('/api/students/fees', (req, res) => {
    const actor = getActor(req);
    if (actor.role !== 'ACCOUNTANT') {
      return res.status(403).json({ error: 'Only the Accountant is authorized to create original student financial records.' });
    }

    const data = req.body;
    const total = Number(data.totalAmount) || 0;
    const paid = Number(data.paidAmount) || 0;
    const balance = calculateBalance(total, paid);
    const paymentStatus = calculatePaymentStatus(total, paid, data.dueDate);

    // Check duplicate invoice
    if (studentFees.some(f => f.invoiceNumber.toLowerCase() === data.invoiceNumber.trim().toLowerCase())) {
      return res.status(400).json({ error: `Invoice number ${data.invoiceNumber} already exists.` });
    }

    const newRecord: StudentFeeRecord = {
      id: `fee-${Date.now()}`,
      studentId: data.studentId,
      studentName: data.studentName,
      gradeClass: data.gradeClass,
      invoiceNumber: data.invoiceNumber.trim(),
      category: data.category,
      totalAmount: total,
      paidAmount: paid,
      balance,
      paymentStatus,
      billIssueDate: data.billIssueDate || new Date().toISOString().split('T')[0],
      dueDate: data.dueDate,
      lastPaymentDate: paid > 0 ? (data.billIssueDate || new Date().toISOString().split('T')[0]) : undefined,
      month: data.month,
      year: Number(data.year) || 2026,
      notes: data.notes || '',
      createdBy: `${actor.name} (${actor.role})`,
      createdByRole: actor.role,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    studentFees.unshift(newRecord);

    // If initial payment was provided, create payment record
    if (paid > 0) {
      payments.unshift({
        id: `pay-${Date.now()}`,
        recordId: newRecord.id,
        recordType: 'student',
        invoiceNumber: newRecord.invoiceNumber,
        paymentNumber: `PAY-STD-${newRecord.id.slice(-4)}-01`,
        amount: paid,
        paymentDate: newRecord.billIssueDate,
        paymentMethod: data.paymentMethod || 'BANK_TRANSFER',
        referenceNumber: data.paymentRef || 'INITIAL-RECEIPT',
        receiptNotes: 'Initial payment recorded during fee creation',
        recordedBy: actor.name,
        recordedByRole: actor.role,
        createdAt: new Date().toISOString(),
      });
    }

    logAudit('RECORD_CREATED', 'StudentFeeRecord', newRecord.id, newRecord.invoiceNumber, actor, {
      newValues: {
        student: newRecord.studentName,
        total: newRecord.totalAmount,
        paid: newRecord.paidAmount,
        month: newRecord.month,
        year: newRecord.year,
      },
    });

    res.status(201).json(newRecord);
  });

  // Critical Check: GM Can NOT edit or delete original records!
  app.put('/api/students/fees/:id', (req, res) => {
    const actor = getActor(req);
    const record = studentFees.find(f => f.id === req.params.id);
    if (!record) return res.status(404).json({ error: 'Record not found' });

    // ENFORCE NON-NEGOTIABLE CRITICAL RULE
    if (actor.role === 'GM') {
      return res.status(403).json({
        error: 'CRITICAL SECURITY VIOLATION: The GM can view and monitor financial records, but CANNOT edit or overwrite original financial records uploaded by the Accountant. Request a correction or flag the record instead.',
      });
    }

    if (actor.role !== 'ACCOUNTANT') {
      return res.status(403).json({ error: 'Only the Accountant can directly edit original records. HOD must use the revision workflow.' });
    }

    const prev = { ...record };
    const data = req.body;
    record.totalAmount = Number(data.totalAmount) || record.totalAmount;
    record.dueDate = data.dueDate || record.dueDate;
    record.month = data.month || record.month;
    record.year = Number(data.year) || record.year;
    record.category = data.category || record.category;
    record.notes = data.notes !== undefined ? data.notes : record.notes;
    record.balance = calculateBalance(record.totalAmount, record.paidAmount);
    record.paymentStatus = calculatePaymentStatus(record.totalAmount, record.paidAmount, record.dueDate);
    record.lastUpdatedBy = `${actor.name} (${actor.role})`;
    record.updatedAt = new Date().toISOString();

    logAudit('RECORD_EDITED', 'StudentFeeRecord', record.id, record.invoiceNumber, actor, {
      previousValues: { total: prev.totalAmount, dueDate: prev.dueDate, category: prev.category },
      newValues: { total: record.totalAmount, dueDate: record.dueDate, category: record.category },
    });

    res.json(record);
  });

  app.delete('/api/students/fees/:id', (req, res) => {
    const actor = getActor(req);
    const index = studentFees.findIndex(f => f.id === req.params.id);
    if (index === -1) return res.status(404).json({ error: 'Record not found' });

    // CRITICAL SECURITY RULE: GM CANNOT DELETE ACCOUNTANT RECORDS
    if (actor.role === 'GM') {
      return res.status(403).json({
        error: 'CRITICAL SECURITY VIOLATION: The GM cannot delete original financial records uploaded by the Accountant.',
      });
    }

    if (actor.role !== 'ACCOUNTANT') {
      return res.status(403).json({ error: 'Unauthorized to delete financial records.' });
    }

    const [deleted] = studentFees.splice(index, 1);
    logAudit('RECORD_EDITED', 'StudentFeeRecord', deleted.id, deleted.invoiceNumber, actor, {
      previousValues: deleted,
      reason: 'Record deleted / archived by Accountant',
    });

    res.json({ success: true, message: 'Record removed successfully' });
  });

  // Flag for review (GM / HOD action)
  app.post('/api/students/fees/:id/flag', (req, res) => {
    const actor = getActor(req);
    if (actor.role !== 'GM' && actor.role !== 'HOD') {
      return res.status(403).json({ error: 'Only GM or HOD can flag records for review.' });
    }

    const record = studentFees.find(f => f.id === req.params.id);
    if (!record) return res.status(404).json({ error: 'Record not found' });

    const { reason, unflag } = req.body;
    if (unflag) {
      record.isFlaggedForReview = false;
      record.flagReason = undefined;
      record.flaggedBy = undefined;
      logAudit('RECORD_FLAGGED', 'StudentFeeRecord', record.id, record.invoiceNumber, actor, {
        reason: 'Flag resolved by reviewer',
      });
    } else {
      record.isFlaggedForReview = true;
      record.flagReason = reason || 'Flagged for review';
      record.flaggedBy = `${actor.name} (${actor.role})`;
      logAudit('RECORD_FLAGGED', 'StudentFeeRecord', record.id, record.invoiceNumber, actor, {
        reason: record.flagReason,
      });

      // Push notification
      notifications.unshift({
        id: `notif-${Date.now()}`,
        title: `Review Requested: ${record.studentName}`,
        message: `${actor.name} (${actor.role}) flagged bill ${record.invoiceNumber}: "${reason}"`,
        type: 'FLAG',
        timestamp: new Date().toISOString(),
        isRead: false,
        targetTab: 'students',
        recipientRoles: ['ACCOUNTANT', 'HOD'],
      });
    }

    res.json(record);
  });

  // HOD Authorized Revision workflow
  app.post('/api/students/fees/:id/revision', (req, res) => {
    const actor = getActor(req);
    if (actor.role !== 'HOD' && actor.role !== 'ACCOUNTANT') {
      return res.status(403).json({ error: 'Only HOD or Accountant can submit authorized revisions.' });
    }

    const record = studentFees.find(f => f.id === req.params.id);
    if (!record) return res.status(404).json({ error: 'Record not found' });

    const { field, newValue, reason } = req.body;
    if (!reason || String(reason).trim() === '') {
      return res.status(400).json({ error: 'A valid reason is required for every authorized revision.' });
    }

    const oldValue = (record as any)[field];
    (record as any)[field] = newValue;

    // Recalculate if financial fields changed
    if (field === 'totalAmount' || field === 'dueDate') {
      record.balance = calculateBalance(record.totalAmount, record.paidAmount);
      record.paymentStatus = calculatePaymentStatus(record.totalAmount, record.paidAmount, record.dueDate);
    }

    record.lastUpdatedBy = `${actor.name} (HOD Revision)`;
    record.updatedAt = new Date().toISOString();
    record.isFlaggedForReview = false; // Resolved by revision

    logAudit('HOD_REVISION', 'StudentFeeRecord', record.id, record.invoiceNumber, actor, {
      previousValues: { [field]: oldValue },
      newValues: { [field]: newValue },
      reason,
    });

    res.json(record);
  });

  // Record Payment against Student Fee
  app.post('/api/students/fees/:id/payments', (req, res) => {
    const actor = getActor(req);
    if (actor.role !== 'ACCOUNTANT' && actor.role !== 'HOD') {
      return res.status(403).json({ error: 'Only Accountant or HOD can record payments.' });
    }

    const record = studentFees.find(f => f.id === req.params.id);
    if (!record) return res.status(404).json({ error: 'Record not found' });

    const amount = Number(req.body.amount);
    if (isNaN(amount) || amount <= 0) {
      return res.status(400).json({ error: 'Payment amount must be greater than zero.' });
    }

    if (amount > record.balance) {
      return res.status(400).json({ error: `Payment amount (PKR ${amount}) exceeds remaining balance (PKR ${record.balance}).` });
    }

    record.paidAmount += amount;
    record.balance = calculateBalance(record.totalAmount, record.paidAmount);
    record.lastPaymentDate = req.body.paymentDate || new Date().toISOString().split('T')[0];
    record.paymentStatus = calculatePaymentStatus(record.totalAmount, record.paidAmount, record.dueDate);
    record.lastUpdatedBy = `${actor.name} (${actor.role})`;
    record.updatedAt = new Date().toISOString();

    const paymentEntry: Payment = {
      id: `pay-${Date.now()}`,
      recordId: record.id,
      recordType: 'student',
      invoiceNumber: record.invoiceNumber,
      paymentNumber: `PAY-STD-${record.id.slice(-4)}-${payments.filter(p => p.recordId === record.id).length + 1}`,
      amount,
      paymentDate: record.lastPaymentDate || new Date().toISOString().split('T')[0],
      paymentMethod: req.body.paymentMethod || 'BANK_TRANSFER',
      referenceNumber: req.body.referenceNumber || `REF-${Date.now()}`,
      receiptNotes: req.body.receiptNotes || 'Student fee payment settlement',
      recordedBy: actor.name,
      recordedByRole: actor.role,
      createdAt: new Date().toISOString(),
    };
    payments.unshift(paymentEntry);

    logAudit('PAYMENT_RECORDED', 'StudentFeeRecord', record.id, record.invoiceNumber, actor, {
      newValues: {
        amountPaid: amount,
        paymentNumber: paymentEntry.paymentNumber,
        newBalance: record.balance,
        status: record.paymentStatus,
      },
    });

    res.json({ record, payment: paymentEntry });
  });

  // ===================== CATEGORY 2: VENDOR PAYABLES API =====================
  app.get('/api/vendors/invoices', (req, res) => {
    const actor = getActor(req);
    let records = [...vendorInvoices];

    // VENDOR ISOLATION: A vendor can ONLY view their own records!
    if (actor.role === 'VENDOR') {
      records = records.filter(r => r.vendorId === actor.vendorId);
      // Apply vendor-safe filters
      const { month, year, status, search, start_date, end_date, ordering, page, page_size } = req.query;
      if (month && month !== 'all') records = records.filter(r => r.month.toLowerCase() === String(month).toLowerCase());
      if (year && year !== 'all') records = records.filter(r => r.year === Number(year));
      if (status && status !== 'all') records = records.filter(r => r.paymentStatus === status);
      if (search) {
        const q = String(search).toLowerCase();
        records = records.filter(r => r.invoiceNumber.toLowerCase().includes(q) || r.description.toLowerCase().includes(q));
      }
      if (start_date) records = records.filter(r => r.issueDate >= String(start_date));
      if (end_date) records = records.filter(r => r.issueDate <= String(end_date));

      // Order
      const orderField = String(ordering || '-created_at');
      const isDesc = orderField.startsWith('-');
      const field = isDesc ? orderField.slice(1) : orderField;
      records.sort((a: any, b: any) => {
        let cmp = 0;
        if (field === 'date' || field === 'issueDate') cmp = new Date(a.issueDate).getTime() - new Date(b.issueDate).getTime();
        else if (field === 'amount' || field === 'totalAmount') cmp = a.totalAmount - b.totalAmount;
        else if (field === 'balance') cmp = a.balance - b.balance;
        else cmp = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
        return isDesc ? -cmp : cmp;
      });

      const totalCount = records.length;
      const pageNum = Math.max(1, Number(page) || 1);
      const pageSz = Math.min(100, Math.max(1, Number(page_size) || 15));
      const totalPages = Math.ceil(totalCount / pageSz) || 1;
      return res.json({ results: records.slice((pageNum - 1) * pageSz, pageNum * pageSz), totalCount, page: pageNum, pageSize: pageSz, totalPages });
    }

    const { month, year, status, search, category, vendorId,
            start_date, end_date, min_amount, max_amount,
            created_by, ordering, page, page_size, flagged_only } = req.query;

    // Core filters
    if (month && month !== 'all') records = records.filter(r => r.month.toLowerCase() === String(month).toLowerCase());
    if (year && year !== 'all') records = records.filter(r => r.year === Number(year));
    if (status && status !== 'all') records = records.filter(r => r.paymentStatus === status);
    if (category && category !== 'all') records = records.filter(r => r.category === category);
    if (vendorId && vendorId !== 'all') records = records.filter(r => r.vendorId === vendorId);
    if (search) {
      const q = String(search).toLowerCase();
      records = records.filter(r =>
        r.vendorName.toLowerCase().includes(q) ||
        r.invoiceNumber.toLowerCase().includes(q) ||
        r.description.toLowerCase().includes(q)
      );
    }

    // Date range (issue date)
    if (start_date) records = records.filter(r => r.issueDate >= String(start_date));
    if (end_date) records = records.filter(r => r.issueDate <= String(end_date));

    // Amount range
    if (min_amount) records = records.filter(r => r.totalAmount >= Number(min_amount));
    if (max_amount) records = records.filter(r => r.totalAmount <= Number(max_amount));

    // Created by
    if (created_by && created_by !== 'all') records = records.filter(r => r.createdBy.includes(String(created_by)));

    // Flagged only
    if (flagged_only === 'true') records = records.filter(r => r.isFlaggedForReview);

    // Ordering
    const orderField = String(ordering || '-created_at');
    const isDesc = orderField.startsWith('-');
    const field = isDesc ? orderField.slice(1) : orderField;
    records.sort((a: any, b: any) => {
      let cmp = 0;
      if (field === 'name' || field === 'vendorName') cmp = (a.vendorName || '').localeCompare(b.vendorName || '');
      else if (field === 'amount' || field === 'totalAmount') cmp = a.totalAmount - b.totalAmount;
      else if (field === 'balance') cmp = a.balance - b.balance;
      else if (field === 'date' || field === 'issueDate') cmp = new Date(a.issueDate).getTime() - new Date(b.issueDate).getTime();
      else if (field === 'dueDate') cmp = new Date(a.dueDate).getTime() - new Date(b.dueDate).getTime();
      else if (field === 'status') cmp = (a.paymentStatus || '').localeCompare(b.paymentStatus || '');
      else cmp = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
      return isDesc ? -cmp : cmp;
    });

    // Pagination
    const totalCount = records.length;
    const pageNum = Math.max(1, Number(page) || 1);
    const pageSz = Math.min(100, Math.max(1, Number(page_size) || 15));
    const totalPages = Math.ceil(totalCount / pageSz) || 1;
    const paginatedRecords = records.slice((pageNum - 1) * pageSz, pageNum * pageSz);

    res.json({
      results: paginatedRecords,
      totalCount,
      page: pageNum,
      pageSize: pageSz,
      totalPages,
    });
  });

  app.post('/api/vendors/invoices', (req, res) => {
    const actor = getActor(req);
    if (actor.role !== 'ACCOUNTANT') {
      return res.status(403).json({ error: 'Only the Accountant is authorized to enter vendor bills.' });
    }

    const data = req.body;
    const total = Number(data.totalAmount) || 0;
    const paid = Number(data.paidAmount) || 0;
    const balance = calculateBalance(total, paid);
    const paymentStatus = calculatePaymentStatus(total, paid, data.dueDate);

    if (vendorInvoices.some(i => i.invoiceNumber.toLowerCase() === data.invoiceNumber.trim().toLowerCase())) {
      return res.status(400).json({ error: `Invoice number ${data.invoiceNumber} already exists.` });
    }

    const newRecord: VendorInvoice = {
      id: `vinv-${Date.now()}`,
      vendorId: data.vendorId,
      vendorName: data.vendorName,
      invoiceNumber: data.invoiceNumber.trim(),
      category: data.category,
      description: data.description || '',
      totalAmount: total,
      paidAmount: paid,
      balance,
      paymentStatus,
      issueDate: data.issueDate || new Date().toISOString().split('T')[0],
      dueDate: data.dueDate,
      lastPaymentDate: paid > 0 ? (data.issueDate || new Date().toISOString().split('T')[0]) : undefined,
      month: data.month,
      year: Number(data.year) || 2026,
      notes: data.notes || '',
      attachmentName: data.attachmentName || '',
      createdBy: `${actor.name} (${actor.role})`,
      createdByRole: actor.role,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    vendorInvoices.unshift(newRecord);

    if (paid > 0) {
      payments.unshift({
        id: `pay-${Date.now()}`,
        recordId: newRecord.id,
        recordType: 'vendor',
        invoiceNumber: newRecord.invoiceNumber,
        paymentNumber: `PAY-VND-${newRecord.id.slice(-4)}-01`,
        amount: paid,
        paymentDate: newRecord.issueDate,
        paymentMethod: data.paymentMethod || 'BANK_TRANSFER',
        referenceNumber: data.paymentRef || 'INITIAL-DISBURSEMENT',
        receiptNotes: 'Initial vendor disbursement',
        recordedBy: actor.name,
        recordedByRole: actor.role,
        createdAt: new Date().toISOString(),
      });
    }

    logAudit('RECORD_CREATED', 'VendorInvoice', newRecord.id, newRecord.invoiceNumber, actor, {
      newValues: {
        vendor: newRecord.vendorName,
        total: newRecord.totalAmount,
        paid: newRecord.paidAmount,
        month: newRecord.month,
        year: newRecord.year,
      },
    });

    res.status(201).json(newRecord);
  });

  // Critical Check: GM Can NOT edit original vendor records!
  app.put('/api/vendors/invoices/:id', (req, res) => {
    const actor = getActor(req);
    const record = vendorInvoices.find(i => i.id === req.params.id);
    if (!record) return res.status(404).json({ error: 'Invoice not found' });

    if (actor.role === 'GM') {
      return res.status(403).json({
        error: 'CRITICAL SECURITY VIOLATION: The GM cannot edit or overwrite original financial records uploaded by the Accountant. Request a correction or flag the invoice instead.',
      });
    }

    if (actor.role !== 'ACCOUNTANT') {
      return res.status(403).json({ error: 'Only the Accountant can edit original invoices. HOD must use the revision workflow.' });
    }

    const data = req.body;
    record.totalAmount = Number(data.totalAmount) || record.totalAmount;
    record.description = data.description || record.description;
    record.dueDate = data.dueDate || record.dueDate;
    record.month = data.month || record.month;
    record.year = Number(data.year) || record.year;
    record.category = data.category || record.category;
    record.notes = data.notes !== undefined ? data.notes : record.notes;
    record.balance = calculateBalance(record.totalAmount, record.paidAmount);
    record.paymentStatus = calculatePaymentStatus(record.totalAmount, record.paidAmount, record.dueDate);
    record.lastUpdatedBy = `${actor.name} (${actor.role})`;
    record.updatedAt = new Date().toISOString();

    logAudit('RECORD_EDITED', 'VendorInvoice', record.id, record.invoiceNumber, actor, {
      newValues: { total: record.totalAmount, dueDate: record.dueDate },
    });

    res.json(record);
  });

  // Record multiple payments against a single vendor invoice
  app.post('/api/vendors/invoices/:id/payments', (req, res) => {
    const actor = getActor(req);
    if (actor.role !== 'ACCOUNTANT' && actor.role !== 'HOD') {
      return res.status(403).json({ error: 'Only Accountant or HOD can record payments.' });
    }

    const record = vendorInvoices.find(i => i.id === req.params.id);
    if (!record) return res.status(404).json({ error: 'Invoice not found' });

    const amount = Number(req.body.amount);
    if (isNaN(amount) || amount <= 0) {
      return res.status(400).json({ error: 'Payment amount must be greater than zero.' });
    }

    if (amount > record.balance) {
      return res.status(400).json({ error: `Payment amount (PKR ${amount}) exceeds remaining balance (PKR ${record.balance}).` });
    }

    record.paidAmount += amount;
    record.balance = calculateBalance(record.totalAmount, record.paidAmount);
    record.lastPaymentDate = req.body.paymentDate || new Date().toISOString().split('T')[0];
    record.paymentStatus = calculatePaymentStatus(record.totalAmount, record.paidAmount, record.dueDate);
    record.lastUpdatedBy = `${actor.name} (${actor.role})`;
    record.updatedAt = new Date().toISOString();

    const paymentEntry: Payment = {
      id: `pay-${Date.now()}`,
      recordId: record.id,
      recordType: 'vendor',
      invoiceNumber: record.invoiceNumber,
      paymentNumber: `PAY-VND-${record.id.slice(-4)}-${payments.filter(p => p.recordId === record.id).length + 1}`,
      amount,
      paymentDate: record.lastPaymentDate || new Date().toISOString().split('T')[0],
      paymentMethod: req.body.paymentMethod || 'BANK_TRANSFER',
      referenceNumber: req.body.referenceNumber || `VND-REF-${Date.now()}`,
      receiptNotes: req.body.receiptNotes || 'Vendor installment settlement',
      recordedBy: actor.name,
      recordedByRole: actor.role,
      createdAt: new Date().toISOString(),
    };
    payments.unshift(paymentEntry);

    logAudit('PAYMENT_RECORDED', 'VendorInvoice', record.id, record.invoiceNumber, actor, {
      newValues: {
        paymentAmount: amount,
        paymentNumber: paymentEntry.paymentNumber,
        remainingPayable: record.balance,
        status: record.paymentStatus,
      },
    });

    res.json({ record, payment: paymentEntry });
  });

  // Vendor lists & details
  app.get('/api/vendors/list', (req, res) => {
    res.json(vendors);
  });

  app.get('/api/students/list', (req, res) => {
    res.json(students);
  });

  // Get payments list - with full filtering
  app.get('/api/payments', (req, res) => {
    const actor = getActor(req);
    const { recordId, invoiceNumber, search, recordType, paymentMethod,
            month, year, start_date, end_date, min_amount, max_amount,
            ordering, page, page_size } = req.query;
    let list = [...payments];

    if (actor.role === 'VENDOR') {
      const vendorInvs = vendorInvoices.filter(i => i.vendorId === actor.vendorId).map(i => i.id);
      list = list.filter(p => vendorInvs.includes(p.recordId));
    }

    if (recordId) list = list.filter(p => p.recordId === recordId);
    if (invoiceNumber) list = list.filter(p => p.invoiceNumber === invoiceNumber);
    if (recordType && recordType !== 'all') list = list.filter(p => p.recordType === recordType);
    if (paymentMethod && paymentMethod !== 'all') list = list.filter(p => p.paymentMethod === paymentMethod);

    // Search
    if (search) {
      const q = String(search).toLowerCase();
      list = list.filter(p =>
        p.paymentNumber.toLowerCase().includes(q) ||
        p.invoiceNumber.toLowerCase().includes(q) ||
        p.referenceNumber.toLowerCase().includes(q) ||
        (p.receiptNotes && p.receiptNotes.toLowerCase().includes(q)) ||
        p.recordedBy.toLowerCase().includes(q)
      );
    }

    // Date range (payment date)
    if (start_date) list = list.filter(p => p.paymentDate >= String(start_date));
    if (end_date) list = list.filter(p => p.paymentDate <= String(end_date));

    // Amount range
    if (min_amount) list = list.filter(p => p.amount >= Number(min_amount));
    if (max_amount) list = list.filter(p => p.amount <= Number(max_amount));

    // Month/year filter on payment date
    if (month && month !== 'all') {
      const monthNames = ['january','february','march','april','may','june','july','august','september','october','november','december'];
      const monthIdx = monthNames.indexOf(String(month).toLowerCase());
      if (monthIdx >= 0) list = list.filter(p => new Date(p.paymentDate).getMonth() === monthIdx);
    }
    if (year && year !== 'all') list = list.filter(p => new Date(p.paymentDate).getFullYear() === Number(year));

    // Ordering
    const orderField = String(ordering || '-created_at');
    const isDesc = orderField.startsWith('-');
    const field = isDesc ? orderField.slice(1) : orderField;
    list.sort((a: any, b: any) => {
      let cmp = 0;
      if (field === 'date' || field === 'paymentDate') cmp = new Date(a.paymentDate).getTime() - new Date(b.paymentDate).getTime();
      else if (field === 'amount') cmp = a.amount - b.amount;
      else cmp = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
      return isDesc ? -cmp : cmp;
    });

    // Pagination
    const totalCount = list.length;
    const pageNum = Math.max(1, Number(page) || 1);
    const pageSz = Math.min(100, Math.max(1, Number(page_size) || 15));
    const totalPages = Math.ceil(totalCount / pageSz) || 1;

    res.json({
      results: list.slice((pageNum - 1) * pageSz, pageNum * pageSz),
      totalCount,
      page: pageNum,
      pageSize: pageSz,
      totalPages,
    });
  });

  // Audit Logs API - with strict role-based visibility matrix
  app.get('/api/audit-logs', (req, res) => {
    const actor = getActor(req);
    if (actor.role === 'VENDOR') {
      return res.status(403).json({ error: 'Vendors do not have access to audit logs' });
    }

    let list = [...auditLogs];

    // STRICT HIERARCHICAL AUDIT LOG VISIBILITY MATRIX:
    // 1. Accountant: ONLY view changes and log entries they personally made
    if (actor.role === 'ACCOUNTANT') {
      list = list.filter(a => a.performedBy === actor.name || (a.user && a.user === actor.name));
    }
    // 2. HOD (Admin): view audit trail and activity logs generated EXCLUSIVELY by the Accountant (zero Super Admin logs)
    else if (actor.role === 'HOD') {
      list = list.filter(a => a.performedByRole === 'ACCOUNTANT');
    }
    // 3. GM / Super Admin: view BOTH their own audit entries AND all entries made by the Accountant
    else if (actor.role === 'GM') {
      list = list.filter(a => a.performedByRole === 'GM' || a.performedByRole === 'ACCOUNTANT');
    } else {
      return res.status(403).json({ error: 'Unauthorized to access audit logs' });
    }

    const { search, action, modelName, performedByRole,
            start_date, end_date, ordering, page, page_size } = req.query;
    if (action && action !== 'all') list = list.filter(a => a.action === action);
    if (modelName && modelName !== 'all') list = list.filter(a => a.modelName === modelName);
    if (performedByRole && performedByRole !== 'all') list = list.filter(a => a.performedByRole === performedByRole);
    if (search) {
      const q = String(search).toLowerCase();
      list = list.filter(a =>
        a.recordIdentifier.toLowerCase().includes(q) ||
        a.performedBy.toLowerCase().includes(q) ||
        (a.reason && a.reason.toLowerCase().includes(q))
      );
    }

    // Date range on timestamp
    if (start_date) list = list.filter(a => a.timestamp >= String(start_date));
    if (end_date) list = list.filter(a => a.timestamp <= String(end_date) + 'T23:59:59');

    // Ordering
    const orderField = String(ordering || '-timestamp');
    const isDesc = orderField.startsWith('-');
    const field = isDesc ? orderField.slice(1) : orderField;
    list.sort((a: any, b: any) => {
      const cmp = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
      return isDesc ? -cmp : cmp;
    });

    // Pagination
    const totalCount = list.length;
    const pageNum = Math.max(1, Number(page) || 1);
    const pageSz = Math.min(100, Math.max(1, Number(page_size) || 20));
    const totalPages = Math.ceil(totalCount / pageSz) || 1;

    res.json({
      results: list.slice((pageNum - 1) * pageSz, pageNum * pageSz),
      totalCount,
      page: pageNum,
      pageSize: pageSz,
      totalPages,
    });
  });

  // Settings API
  app.get('/api/settings', (req, res) => {
    res.json(settings);
  });

  app.post('/api/settings', (req, res) => {
    const actor = getActor(req);
    if (actor.role !== 'GM') {
      return res.status(403).json({ error: 'Only the GM can modify school settings' });
    }
    const prev = { ...settings };
    settings = { ...settings, ...req.body };
    logAudit('SETTINGS_UPDATED', 'SchoolSettings', 'settings-1', 'School Configuration', actor, {
      previousValues: prev,
      newValues: settings,
      reason: 'School settings updated by GM',
    });
    res.json(settings);
  });

  // Notifications API
  app.get('/api/notifications', (req, res) => {
    const actor = getActor(req);
    const roleNotifs = notifications.filter(n => !n.recipientRoles || n.recipientRoles.includes(actor.role));
    res.json(roleNotifs);
  });

  app.post('/api/notifications/:id/read', (req, res) => {
    const notif = notifications.find(n => n.id === req.params.id);
    if (notif) notif.isRead = true;
    res.json({ success: true });
  });

  // Bulk Import Validate & Commit
  app.post('/api/import/commit', (req, res) => {
    const actor = getActor(req);
    if (actor.role !== 'ACCOUNTANT') {
      return res.status(403).json({ error: 'Only the Accountant can perform bulk data imports' });
    }

    const { category, rows } = req.body;
    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(400).json({ error: 'No rows provided for import' });
    }

    const existingStudentInvoices = new Set(studentFees.map(f => f.invoiceNumber.toUpperCase()));
    const existingVendorInvoices = new Set(vendorInvoices.map(v => v.invoiceNumber.toUpperCase()));

    let importedCount = 0;
    const errors: Array<{ rowNumber: number; errors: string[] }> = [];

    if (category === 'student_fees') {
      rows.forEach((row, idx) => {
        const validation = validateStudentImportRow(row, existingStudentInvoices);
        if (!validation.isValid) {
          errors.push({ rowNumber: idx + 1, errors: validation.errors });
        } else {
          existingStudentInvoices.add(String(row.invoiceNumber).toUpperCase());
          const total = Number(row.totalAmount);
          const paid = Number(row.paidAmount || 0);
          const balance = calculateBalance(total, paid);
          const paymentStatus = calculatePaymentStatus(total, paid, row.dueDate);

          const newRecord: StudentFeeRecord = {
            id: `fee-imp-${Date.now()}-${idx}`,
            studentId: row.studentId,
            studentName: row.studentName,
            gradeClass: row.gradeClass,
            invoiceNumber: row.invoiceNumber.trim(),
            category: row.category,
            totalAmount: total,
            paidAmount: paid,
            balance,
            paymentStatus,
            billIssueDate: new Date().toISOString().split('T')[0],
            dueDate: row.dueDate,
            lastPaymentDate: paid > 0 ? new Date().toISOString().split('T')[0] : undefined,
            month: row.month,
            year: Number(row.year) || 2026,
            notes: row.notes || 'Bulk imported via spreadsheet',
            createdBy: `${actor.name} (Accountant Import)`,
            createdByRole: 'ACCOUNTANT',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          };
          studentFees.unshift(newRecord);
          importedCount++;
        }
      });
    }

    logAudit('IMPORT_COMPLETED', 'StudentFeeRecord', `batch-${Date.now()}`, `${importedCount} rows`, actor, {
      newValues: { importedRows: importedCount, rejectedRows: errors.length },
      reason: `Bulk import completed by ${actor.name}`,
    });

    res.json({
      success: true,
      importedCount,
      rejectedCount: errors.length,
      errors,
    });
  });

  // Mount Vite middleware in development
  const isDev = process.env.NODE_ENV !== 'production';
  if (isDev) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static('dist'));
    app.get('*', (req, res) => {
      res.sendFile('index.html', { root: 'dist' });
    });
  }

  const DEFAULT_PORT = Number(process.env.PORT) || 3000;

  function startListening(port: number) {
    const server = app.listen(port, '0.0.0.0', () => {
      console.log(`\n======================================================`);
      console.log(`  Smart School (EduFinance Pro) Server is RUNNING!`);
      console.log(`  Access the app at: http://localhost:${port}`);
      console.log(`  Network access at: http://0.0.0.0:${port}`);
      console.log(`======================================================\n`);
    });

    server.on('error', (err: any) => {
      if (err.code === 'EADDRINUSE') {
        console.warn(`[Server] Port ${port} is currently in use. Retrying on port ${port + 1}...`);
        startListening(port + 1);
      } else {
        console.error('Fatal server startup error:', err);
        process.exit(1);
      }
    });
  }

  startListening(DEFAULT_PORT);
}

startServer().catch(err => {
  console.error('Fatal server startup error:', err);
  process.exit(1);
});

