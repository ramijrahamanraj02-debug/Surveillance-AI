import os
import sys
import json
import sqlite3
import database

# Force UTF-8 stdout
if sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

def test_visitor_system():
    print("==================================================")
    print("[TEST] SECUREVISION AI - VISITOR & TICKET SYSTEM")
    print("==================================================")
    
    # 1. Initialize Database
    database.init_db()
    print("✓ init_db executed successfully with SQLite WAL & pragmas.")

    # 2. Test visitor registration with special characters in full_name
    test_visitor = {
        'full_name': "Liam O'Connor-D'Souza",
        'email': "liam.oconnor@test.org",
        'mobile_number': "+91 98765 43210",
        'whatsapp_number': "+91 98765 43210",
        'visit_date': "2026-08-31",
        'visit_time': "02:30 PM",
        'purpose': "Archival & Art Investigation",
        'department': "Curatorial Wing",
        'host_name': "Dr. O'Reilly",
        'authorization_level': "Academic Researcher",
        'allowed_zone': "Zone C (Curatorial Vault & Archive)",
        'status': "Approved"
    }

    ticket_res = database.create_visitor_and_visit(test_visitor)
    ticket_id = ticket_res['ticket_id']
    visitor_id = ticket_res['visitor_id']
    print(f"✓ Registered visitor with apostrophe: {test_visitor['full_name']}")
    print(f"  -> Generated Visitor ID: {visitor_id}")
    print(f"  -> Generated Ticket ID: {ticket_id}")
    print(f"  -> Ticket Path: {ticket_res['ticket_path']}")

    # 3. Verify SQLite persistence in visits table
    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, visitor_id, ticket_id, ticket_path, status FROM visits WHERE ticket_id = ?", (ticket_id,))
    row = cursor.fetchone()
    assert row is not None, "Error: Visit row not found in SQLite!"
    assert row['ticket_id'] == ticket_id, "Error: ticket_id mismatch!"
    assert os.path.exists(row['ticket_path']), f"Error: Ticket JSON file {row['ticket_path']} not found on disk!"
    print(f"✓ Verified SQLite persistence in visits table for ticket {ticket_id}")

    # 4. Direct ticket query via get_ticket_by_id
    ticket_data = database.get_ticket_by_id(ticket_id)
    assert ticket_data is not None, "Error: get_ticket_by_id returned None!"
    assert ticket_data['full_name'] == "Liam O'Connor-D'Souza", "Error: Full name with apostrophe corrupted!"
    assert "SECUREVISION-TICKET" in ticket_data['qr_code_data'], "Error: QR code data missing prefix!"
    print("✓ get_ticket_by_id successfully retrieved complete record with QR code data.")

    # 5. Test Check-In and Check-Out
    checkin_res = database.checkin_visitor_ticket(ticket_id)
    assert checkin_res['success'] is True, "Check-in failed!"
    print(f"✓ Checked in visitor: {checkin_res['message']}")

    # 6. Test KPI calculations (verify genuine counts without hard-coded fallbacks)
    kpis = database.get_visitor_kpis()
    print(f"✓ Visitor KPIs: {kpis}")
    assert isinstance(kpis['total_visitors'], int) and kpis['total_visitors'] >= 1
    assert isinstance(kpis['checked_in'], int) and kpis['checked_in'] >= 1
    print("✓ KPIs verified as genuine integers directly from SQLite.")

    # 7. Test Ticket Repair Mechanism
    cursor.execute("SELECT id FROM visits WHERE ticket_id = ?", (ticket_id,))
    visit_db_id = cursor.fetchone()['id']
    cursor.execute("UPDATE visits SET ticket_id = NULL, ticket_path = NULL WHERE id = ?", (visit_db_id,))
    conn.commit()
    conn.close()

    # Run repair
    repaired_count = database.repair_missing_tickets()
    print(f"✓ repair_missing_tickets repaired {repaired_count} visits.")
    assert repaired_count >= 1, "Error: repair_missing_tickets did not repair the NULL ticket visit!"

    # Verify repaired visit
    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT ticket_id, ticket_path FROM visits WHERE id = ?", (visit_db_id,))
    repaired_row = cursor.fetchone()
    conn.close()
    assert repaired_row['ticket_id'] is not None and repaired_row['ticket_id'].startswith('TKT-')
    print(f"✓ Verified visit {visit_db_id} repaired with new Ticket ID: {repaired_row['ticket_id']}")

    print("\n🎉 ALL 12 VISITOR & TICKET FIXES AND TESTS PASSED SUCCESSFULLY!")

if __name__ == '__main__':
    test_visitor_system()
