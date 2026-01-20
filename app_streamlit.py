# ==========================
# SISTEM DATA PENDUDUK STREAMLIT SUPER LENGKAP (FIX) - VERSION AMAN
# DENGAN ENKRIPSI, LOGIN ADMIN, STATISTIK, DAN FITUR PENCARIAN
# + FITUR UPLOAD DATA MASAL
# ==========================

import streamlit as st
import pandas as pd
import sqlite3
import bcrypt
import os
import time
import secrets
import hashlib
from datetime import datetime, timedelta
import io


# ================= KONFIGURASI KEAMANAN =================
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 menit dalam detik
SESSION_TIMEOUT = 1800  # 30 menit dalam detik

# ================= FUNGSI KEAMANAN =================
def hash_password(password: str) -> str:
    """Hash password menggunakan bcrypt"""
    salt = bcrypt.gensalt(rounds=12)  # 12 rounds untuk keamanan optimal
    return bcrypt.hashpw(password.encode(), salt).decode()

def check_password(password: str, hashed: str) -> bool:
    """Verifikasi password dengan hash"""
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except:
        return False

def generate_secure_token() -> str:
    """Generate token aman untuk sesi"""
    return secrets.token_urlsafe(32)

def validate_nik(nik: str) -> bool:
    """Validasi format NIK (16 digit)"""
    if not nik or len(str(nik)) != 16:
        return False
    return str(nik).isdigit()

def validate_input(text: str, max_length: int = 100) -> bool:
    """Validasi input untuk mencegah XSS dan SQL injection"""
    if not text:
        return True
    # Daftar karakter berbahaya
    dangerous_patterns = [';', "'", '"', '--', '/*', '*/', '<script', 'javascript:', 'onload=']
    text_lower = text.lower()
    for pattern in dangerous_patterns:
        if pattern in text_lower:
            return False
    return len(text) <= max_length

# ================= FUNGSI DATABASE =================
def get_connection():
    base_dir = "/home/appuser"   # FOLDER PERSISTENT STREAMLIT
    os.makedirs(base_dir, exist_ok=True)

    db_path = os.path.join(base_dir, "penduduk.db")

    conn = sqlite3.connect(db_path, check_same_thread=False)

    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA secure_delete = ON")

    return conn


def create_table():
    """Membuat tabel penduduk dengan constraint"""
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS penduduk (
            nik TEXT PRIMARY KEY CHECK(length(nik) = 16 AND nik GLOB '[0-9]*'),
            nama TEXT NOT NULL,
            jenis_kelamin TEXT CHECK(jenis_kelamin IN ('Laki-laki', 'Perempuan')),
            alamat TEXT,
            umur INTEGER CHECK(umur >= 0 AND umur <= 150),
            no_kk TEXT,
            status_keluarga TEXT,
            pendidikan TEXT,
            pekerjaan TEXT,
            pkh TEXT CHECK(pkh IN ('Ya', 'Tidak')),
            kks TEXT CHECK(kks IN ('Ya', 'Tidak')),
            pbi_jkn TEXT CHECK(pbi_jkn IN ('Ya', 'Tidak')),
            blt TEXT CHECK(blt IN ('Ya', 'Tidak')),
            koperasi_merah_putih TEXT CHECK(koperasi_merah_putih IN ('Ya', 'Tidak')),
            pip TEXT CHECK(pip IN ('Ya', 'Tidak')),
            subsidi_listrik TEXT CHECK(subsidi_listrik IN ('Ya', 'Tidak')),
            lpg_3kg TEXT CHECK(lpg_3kg IN ('Ya', 'Tidak')),
            punya_ktp TEXT CHECK(punya_ktp IN ('Ya', 'Tidak', 'Dalam Proses')),
            punya_kk TEXT CHECK(punya_kk IN ('Ya', 'Tidak', 'Dalam Proses')),
            dusun TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Buat trigger untuk update timestamp
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS update_timestamp 
        AFTER UPDATE ON penduduk 
        BEGIN
            UPDATE penduduk SET updated_at = CURRENT_TIMESTAMP WHERE rowid = NEW.rowid;
        END;
    """)
    
    conn.commit()
    conn.close()

def create_users_table():
    """Tabel untuk user/admin dengan logging login attempts"""
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL CHECK(length(username) >= 3),
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0 CHECK(is_admin IN (0, 1)),
            can_edit INTEGER DEFAULT 0 CHECK(can_edit IN (0, 1)),
            last_login TIMESTAMP,
            login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            failed_attempts INTEGER DEFAULT 0,
            last_failed_attempt TIMESTAMP
        )
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip_address TEXT,
            user_agent TEXT,
            success INTEGER DEFAULT 0,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reason TEXT
        )
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS data_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            table_name TEXT,
            record_id TEXT,
            change_type TEXT,
            old_values TEXT,
            new_values TEXT,
            changed_by TEXT,
            changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    conn.close()

def is_account_locked(username: str) -> bool:
    """Cek apakah akun terkunci"""
    conn = get_connection()
    cur = conn.cursor()
    
    cur.execute("""
        SELECT locked_until FROM users 
        WHERE username = ? AND locked_until > CURRENT_TIMESTAMP
    """, (username,))
    
    result = cur.fetchone()
    conn.close()
    
    return result is not None

def update_login_attempts(username: str, success: bool):
    """Update jumlah percobaan login (AMAN)"""
    conn = get_connection()
    cur = conn.cursor()

    if success:
        # Reset jika login berhasil
        cur.execute("""
            UPDATE users 
            SET login_attempts = 0,
                failed_attempts = 0,
                locked_until = NULL,
                last_login = CURRENT_TIMESTAMP
            WHERE username = ?
        """, (username,))
    else:
        # Tambah jika login gagal
        cur.execute("""
            UPDATE users
            SET login_attempts = login_attempts + 1,
                failed_attempts = failed_attempts + 1,
                last_failed_attempt = CURRENT_TIMESTAMP
            WHERE username = ?
        """, (username,))

        # Ambil jumlah percobaan
        cur.execute("""
            SELECT login_attempts FROM users WHERE username = ?
        """, (username,))
        row = cur.fetchone()

        if row is None:
            conn.close()
            return  # username tidak ada

        attempts = row[0]

        # Kunci akun jika melebihi batas
        if attempts >= MAX_LOGIN_ATTEMPTS:
            lock_time = datetime.now() + timedelta(seconds=LOCKOUT_TIME)
            cur.execute("""
                UPDATE users
                SET locked_until = ?
                WHERE username = ?
            """, (lock_time.isoformat(), username))

    conn.commit()
    conn.close()



def log_login_attempt(username: str, ip_address: str, user_agent: str, success: bool, reason: str = None):
    """Log setiap percobaan login"""
    conn = get_connection()
    conn.execute("""
        INSERT INTO login_logs (username, ip_address, user_agent, success, reason)
        VALUES (?, ?, ?, ?, ?)
    """, (username, ip_address, user_agent, 1 if success else 0, reason))
    conn.commit()
    conn.close()

def log_data_change(table_name: str, record_id: str, change_type: str, 
                   old_values: dict, new_values: dict, changed_by: str):
    """Log perubahan data untuk audit trail"""
    conn = get_connection()
    conn.execute("""
        INSERT INTO data_changes (table_name, record_id, change_type, old_values, new_values, changed_by)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (table_name, record_id, change_type, 
          str(old_values), str(new_values), changed_by))
    conn.commit()
    conn.close()

# ================= FUNGSI AUTENTIKASI =================
def authenticate_user(username: str, password: str, ip_address: str = None, user_agent: str = None) -> tuple:
    """Verifikasi login user dengan logging"""
    if not validate_input(username) or not validate_input(password):
        log_login_attempt(username, ip_address, user_agent, False, "Invalid input")
        return None
    
    # Cek apakah akun terkunci
    if is_account_locked(username):
        log_login_attempt(username, ip_address, user_agent, False, "Account locked")
        return None
    
    conn = get_connection()
    cur = conn.cursor()
    
    try:
        cur.execute("""
            SELECT username, password_hash, is_admin, can_edit 
            FROM users WHERE username = ?
        """, (username,))
        
        row = cur.fetchone()
        
        if row and check_password(password, row[1]):
            # Login berhasil
            update_login_attempts(username, True)
            log_login_attempt(username, ip_address, user_agent, True)
            
            # Generate session token
            session_token = generate_secure_token()
            st.session_state.session_token = session_token
            st.session_state.last_activity = time.time()
            
            return row[0], row[2], row[3]
        else:
            # Login gagal
            update_login_attempts(username, False)
            log_login_attempt(username, ip_address, user_agent, False, "Invalid credentials")
            return None
    finally:
        conn.close()

def register_user(username: str, password: str, is_admin: bool = False) -> bool:
    """Registrasi user baru dengan validasi"""
    if not validate_input(username) or not validate_input(password):
        return False
    
    if len(password) < 8:
        return False
    
    conn = get_connection()
    try:
        password_hash = hash_password(password)
        
        # Cek apakah ini user pertama (jadi admin otomatis)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        user_count = cur.fetchone()[0]
        
        # Jika belum ada user, yang pertama jadi admin
        if user_count == 0:
            is_admin = True
        
        conn.execute("""
            INSERT INTO users (username, password_hash, is_admin, can_edit)
            VALUES (?, ?, ?, ?)
        """, (username, password_hash, 1 if is_admin else 0, 1 if is_admin else 0))
        
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    except Exception as e:
        st.error(f"Error: {str(e)}")
        return False
    finally:
        conn.close()

def check_session_timeout():
    """Cek apakah sesi sudah timeout"""
    if 'last_activity' not in st.session_state:
        return True
    
    elapsed = time.time() - st.session_state.last_activity
    return elapsed > SESSION_TIMEOUT

def update_session_activity():
    """Update waktu aktivitas terakhir"""
    st.session_state.last_activity = time.time()

# ================= FUNGSI DATA PENDUDUK =================
def is_data_exists() -> bool:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM penduduk")
    count = cur.fetchone()[0]
    conn.close()
    return count > 0

def save_to_db(df: pd.DataFrame):
    """Simpan data ke database (UPSERT AMAN)"""
    conn = get_connection()
    cur = conn.cursor()

    try:
        cols = [
            "nik","nama","jenis_kelamin","alamat","umur","no_kk",
            "status_keluarga","pendidikan","pekerjaan",
            "pkh","kks","pbi_jkn","blt","koperasi_merah_putih",
            "pip","subsidi_listrik","lpg_3kg",
            "punya_ktp","punya_kk","dusun"
        ]

        df = df[cols].fillna("")

        for _, row in df.iterrows():
            cur.execute("""
                INSERT INTO penduduk (
                    nik,nama,jenis_kelamin,alamat,umur,no_kk,
                    status_keluarga,pendidikan,pekerjaan,
                    pkh,kks,pbi_jkn,blt,koperasi_merah_putih,
                    pip,subsidi_listrik,lpg_3kg,
                    punya_ktp,punya_kk,dusun
                )
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(nik) DO UPDATE SET
                    nama=excluded.nama,
                    jenis_kelamin=excluded.jenis_kelamin,
                    alamat=excluded.alamat,
                    umur=excluded.umur,
                    no_kk=excluded.no_kk,
                    status_keluarga=excluded.status_keluarga,
                    pendidikan=excluded.pendidikan,
                    pekerjaan=excluded.pekerjaan,
                    pkh=excluded.pkh,
                    kks=excluded.kks,
                    pbi_jkn=excluded.pbi_jkn,
                    blt=excluded.blt,
                    koperasi_merah_putih=excluded.koperasi_merah_putih,
                    pip=excluded.pip,
                    subsidi_listrik=excluded.subsidi_listrik,
                    lpg_3kg=excluded.lpg_3kg,
                    punya_ktp=excluded.punya_ktp,
                    punya_kk=excluded.punya_kk,
                    dusun=excluded.dusun
            """, tuple(row))

        conn.commit()

        # bersihkan backup data lama
        if 'old_data' in st.session_state:
            del st.session_state.old_data

    except Exception as e:
        conn.rollback()
        st.error(f"❌ Error saving data: {str(e)}")
        raise e

    finally:
        conn.close()


def load_data() -> pd.DataFrame:
    """Load data dari database"""
    conn = get_connection()
    try:
        df = pd.read_sql("SELECT * FROM penduduk", conn)
        return df
    finally:
        conn.close()

def get_statistics(df: pd.DataFrame) -> dict:
    """Hitung statistik lengkap"""
    stats = {
        'total': len(df),
        'laki_laki': 0,
        'perempuan': 0,
        'age_groups': {
            '0-17': 0,
            '18-35': 0,
            '36-50': 0,
            '51-65': 0,
            '65+': 0
        }
    }
    
    if 'jenis_kelamin' in df.columns:
        stats['laki_laki'] = len(df[df['jenis_kelamin'].str.contains('Laki-laki|LAKI-LAKI|L', case=False, na=False)])
        stats['perempuan'] = len(df[df['jenis_kelamin'].str.contains('Perempuan|PEREMPUAN|P', case=False, na=False)])
    
    if 'umur' in df.columns:
        # Hitung kelompok umur
        stats['age_groups']['0-17'] = len(df[(df['umur'] >= 0) & (df['umur'] <= 17)])
        stats['age_groups']['18-35'] = len(df[(df['umur'] >= 18) & (df['umur'] <= 35)])
        stats['age_groups']['36-50'] = len(df[(df['umur'] >= 36) & (df['umur'] <= 50)])
        stats['age_groups']['51-65'] = len(df[(df['umur'] >= 51) & (df['umur'] <= 65)])
        stats['age_groups']['65+'] = len(df[df['umur'] > 65])
    
    return stats

# ================= FUNGSI UPLOAD DATA MASAL =================
def process_uploaded_file(uploaded_file, merge_option: str = "append") -> tuple:
    """
    Proses file Excel yang diupload
    Returns: (success, message, df, invalid_rows)
    """
    try:
        # Baca file Excel
        if uploaded_file.name.endswith('.xlsx') or uploaded_file.name.endswith('.xls'):
            df = pd.read_excel(uploaded_file)
        elif uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file, encoding='utf-8')
        else:
            return False, "Format file tidak didukung. Gunakan Excel (.xlsx, .xls) atau CSV.", None, None
        
        # Validasi kolom minimal
        required_columns = ['nik', 'nama']
        missing_cols = [col for col in required_columns if col not in df.columns]
        
        if missing_cols:
            return False, f"Kolom wajib tidak ditemukan: {', '.join(missing_cols)}", None, None
        
        # Normalisasi nama kolom (ubah ke lowercase)
        df.columns = [col.lower().strip() for col in df.columns]
        
        # Normalisasi kolom
        df = normalize_columns(df)
        
        # Validasi NIK
        df['nik'] = df['nik'].astype(str).str.strip()
        invalid_nik_mask = ~df['nik'].apply(validate_nik)
        
        if invalid_nik_mask.any():
            invalid_rows = df[invalid_nik_mask].copy()
            invalid_rows['alasan'] = 'NIK tidak valid (harus 16 digit angka)'
        else:
            invalid_rows = pd.DataFrame()
        
        # Validasi data lainnya
        validation_errors = []
        
        # Validasi jenis kelamin
        if 'jenis_kelamin' in df.columns:
            valid_genders = ['Laki-laki', 'Perempuan', 'L', 'P']
            invalid_gender = ~df['jenis_kelamin'].isin(valid_genders)
            if invalid_gender.any():
                for idx in df[invalid_gender].index:
                    validation_errors.append({
                        'row': idx + 2,  # +2 karena header + index mulai dari 0
                        'nik': df.loc[idx, 'nik'],
                        'field': 'jenis_kelamin',
                        'value': df.loc[idx, 'jenis_kelamin'],
                        'alasan': 'Harus "Laki-laki" atau "Perempuan"'
                    })
        
        # Validasi umur
        if 'umur' in df.columns:
            try:
                df['umur'] = pd.to_numeric(df['umur'], errors='coerce')
                invalid_age = (df['umur'] < 0) | (df['umur'] > 150)
                if invalid_age.any():
                    for idx in df[invalid_age].index:
                        validation_errors.append({
                            'row': idx + 2,
                            'nik': df.loc[idx, 'nik'],
                            'field': 'umur',
                            'value': df.loc[idx, 'umur'],
                            'alasan': 'Umur harus antara 0-150 tahun'
                        })
            except:
                pass
        
        # Tambahkan validation errors ke invalid_rows
        if validation_errors:
            error_df = pd.DataFrame(validation_errors)
            invalid_rows = pd.concat([invalid_rows, error_df], ignore_index=True)
        
        # Validasi duplikat NIK dalam file
        duplicate_nik = df[df.duplicated('nik', keep=False)]
        if not duplicate_nik.empty:
            for idx in duplicate_nik.index:
                invalid_rows = pd.concat([invalid_rows, pd.DataFrame([{
                    'row': idx + 2,
                    'nik': df.loc[idx, 'nik'],
                    'field': 'nik',
                    'value': df.loc[idx, 'nik'],
                    'alasan': 'NIK duplikat dalam file'
                }])], ignore_index=True)
        
        return True, "File berhasil diproses", df, invalid_rows
        
    except Exception as e:
        return False, f"Error memproses file: {str(e)}", None, None

def upload_data_massal(df_new: pd.DataFrame, merge_option: str = "append", replace_duplicates: bool = True):
    """
    Upload data massal ke database
    """
    try:
        conn = get_connection()
        
        if merge_option == "append":
            # Load data yang sudah ada
            existing_df = load_data()
            existing_niks = set(existing_df['nik'].astype(str))
            
            # Filter data baru yang NIK-nya belum ada
            new_niks = set(df_new['nik'].astype(str))
            duplicate_niks = new_niks.intersection(existing_niks)
            
            if duplicate_niks and not replace_duplicates:
                # Hanya tambah yang belum ada
                df_to_add = df_new[~df_new['nik'].isin(duplicate_niks)]
                duplicate_count = len(df_new) - len(df_to_add)
                message = f"Data ditambahkan: {len(df_to_add)} baris. {duplicate_count} data duplikat diabaikan."
            else:
                # Replace yang duplikat
                df_to_add = df_new
                duplicate_count = len(duplicate_niks)
                message = f"Data ditambahkan/diperbarui: {len(df_to_add)} baris. {duplicate_count} data diperbarui."
            
            # Simpan ke database
            if not df_to_add.empty:
                save_to_db(df_to_add)
            
            return True, message, duplicate_count
            
        elif merge_option == "replace_all":
            # Hapus semua data lama
            conn.execute("DELETE FROM penduduk")
            conn.commit()
            
            # Tambah data baru
            save_to_db(df_new)
            
            return True, f"Semua data diganti dengan {len(df_new)} baris data baru.", len(df_new)
            
        elif merge_option == "update_only":
            # Update hanya data yang sudah ada
            existing_df = load_data()
            existing_niks = set(existing_df['nik'].astype(str))
            
            df_to_update = df_new[df_new['nik'].isin(existing_niks)]
            
            if not df_to_update.empty:
                save_to_db(df_to_update)
                return True, f"{len(df_to_update)} data diperbarui.", len(df_to_update)
            else:
                return False, "Tidak ada data yang bisa diperbarui (NIK tidak ditemukan).", 0
                
    except Exception as e:
        return False, f"Error upload data: {str(e)}", 0
    finally:
        conn.close()

# ================= INISIALISASI DATABASE =================
create_table()
create_users_table()

def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Pastikan semua kolom bansos & identitas selalu ada"""
    default_cols = {
        "pkh": "Tidak",
        "kks": "Tidak",
        "pbi_jkn": "Tidak",
        "blt": "Tidak",
        "koperasi_merah_putih": "Tidak",
        "pip": "Tidak",
        "subsidi_listrik": "Tidak",
        "lpg_3kg": "Tidak",
        "punya_ktp": "Tidak",
        "punya_kk": "Tidak",
        "no_kk": "",
        "jenis_kelamin": "Laki-laki",
        "status_keluarga": "Anggota",
        "pendidikan": "Tidak Sekolah",
        "pekerjaan": "Tidak Bekerja",
        "dusun": "",
        "alamat": "",
        "umur": 0
    }

    for col, default in default_cols.items():
        if col not in df.columns:
            df[col] = default
        else:
            # Clean data
            if col in ['pkh', 'kks', 'pbi_jkn', 'blt', 'koperasi_merah_putih', 
                      'pip', 'subsidi_listrik', 'lpg_3kg', 'punya_ktp', 'punya_kk']:
                df[col] = df[col].astype(str).str.strip()
                # Normalize "Ya"/"Tidak"
                mask_ya = df[col].str.contains('ya|Ya|YA|y|Y|yes|Yes|YES', na=False)
                mask_tidak = df[col].str.contains('tidak|Tidak|TIDAK|no|No|NO|t|T', na=False)
                df.loc[mask_ya, col] = 'Ya'
                df.loc[mask_tidak, col] = 'Tidak'
                
            elif col == 'jenis_kelamin':
                df[col] = df[col].astype(str).str.strip()
                mask_l = df[col].str.contains('laki|laki-laki|Laki|Laki-laki|LAKI|LAKI-LAKI|L|l', na=False)
                mask_p = df[col].str.contains('perempuan|Perempuan|PEREMPUAN|P|p|wanita|Wanita|WANITA', na=False)
                df.loc[mask_l, col] = 'Laki-laki'
                df.loc[mask_p, col] = 'Perempuan'

    return df

# ================= UI UTAMA =================
st.set_page_config(
    page_title="Sistem Data Penduduk",
    layout="wide",
    page_icon="🏠"
)

st.title("🏠 Sistem Informasi Data Penduduk Desa")

# ================= SISTEM SESSION =================
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.is_admin = False
    st.session_state.can_edit = False
    st.session_state.login_attempts = 0
    st.session_state.session_token = None
    st.session_state.last_activity = None

# ================= Cek Session Timeout =================
if st.session_state.logged_in and check_session_timeout():
    st.warning("Sesi Anda telah berakhir. Silakan login kembali.")
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.is_admin = False
    st.session_state.can_edit = False
    st.rerun()

# Update aktivitas sesi jika ada interaksi
if st.session_state.logged_in:
    update_session_activity()

# ================= Sidebar Login/Logout =================
with st.sidebar:
    st.header("🔐 Sistem Login")
    
    if not st.session_state.logged_in:
        # Cek apakah ada user di database
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        user_count = cur.fetchone()[0]
        conn.close()
        
        if user_count == 0:
            st.warning("Belum ada user terdaftar. Silakan buat akun admin pertama.")
            tab1 = st.tabs(["Register Admin Pertama"])[0]
        else:
            tab1, tab2 = st.tabs(["Login", "Register"])
        
        with tab1:
            if user_count == 0:
                st.info("Buat akun admin pertama untuk sistem")
                username = st.text_input("Username (min 3 karakter)", key="reg_admin_user")
                password = st.text_input("Password (min 8 karakter)", type="password", key="reg_admin_pass")
                confirm_pass = st.text_input("Konfirmasi Password", type="password", key="reg_admin_confirm")
                
                if st.button("Buat Admin Pertama", type="primary"):
                    if not username or len(username) < 3:
                        st.error("Username minimal 3 karakter")
                    elif not password or len(password) < 8:
                        st.error("Password minimal 8 karakter")
                    elif password != confirm_pass:
                        st.error("Password tidak cocok")
                    else:
                        if register_user(username, password, True):
                            st.success(f"Akun admin {username} berhasil dibuat! Silakan login.")
                            st.rerun()
                        else:
                            st.error("Gagal membuat akun admin")
            else:
                username = st.text_input("Username", key="login_user")
                password = st.text_input("Password", type="password", key="login_pass")
                
                # Cek login attempts
                if st.session_state.login_attempts >= MAX_LOGIN_ATTEMPTS:
                    st.error(f"Terlalu banyak percobaan login. Tunggu {LOCKOUT_TIME//60} menit.")
                    st.stop()
                
                if st.button("Login", type="primary"):
                    # Dapatkan IP dan User Agent (simulasi)
                    ip_address = "127.0.0.1"  # Dalam produksi, gunakan request.remote_addr
                    user_agent = "Streamlit-App"  # Dalam produksi, gunakan request.headers.get('User-Agent')
                    
                    user_data = authenticate_user(username, password, ip_address, user_agent)
                    if user_data:
                        st.session_state.logged_in = True
                        st.session_state.username = user_data[0]
                        st.session_state.is_admin = bool(user_data[1])
                        st.session_state.can_edit = bool(user_data[2])
                        st.session_state.login_attempts = 0
                        st.success(f"Selamat datang, {username}!")
                        st.rerun()
                    else:
                        st.session_state.login_attempts += 1
                        remaining = MAX_LOGIN_ATTEMPTS - st.session_state.login_attempts
                        st.error(f"Username atau password salah. Percobaan tersisa: {remaining}")
                        
                        if st.session_state.login_attempts >= MAX_LOGIN_ATTEMPTS:
                            st.error(f"Akun terkunci selama {LOCKOUT_TIME//60} menit!")
        
        if user_count > 0:
            with tab2:
                if st.session_state.logged_in and st.session_state.is_admin:
                    new_user = st.text_input("Username Baru (min 3 karakter)")
                    new_pass = st.text_input("Password Baru (min 8 karakter)", type="password")
                    confirm_pass = st.text_input("Konfirmasi Password", type="password")
                    is_admin_new = st.checkbox("Admin User")
                    
                    if st.button("Register User"):
                        if not new_user or len(new_user) < 3:
                            st.error("Username minimal 3 karakter")
                        elif not new_pass or len(new_pass) < 8:
                            st.error("Password minimal 8 karakter")
                        elif new_pass != confirm_pass:
                            st.error("Password tidak cocok")
                        else:
                            if register_user(new_user, new_pass, is_admin_new):
                                st.success(f"User {new_user} berhasil didaftarkan!")
                            else:
                                st.error("Username sudah ada!")
                elif not st.session_state.logged_in:
                    st.info("Hanya admin yang bisa mendaftarkan user baru. Silakan login sebagai admin.")
    
    else:
        # User sudah login
        st.success(f"Login sebagai: **{st.session_state.username}**")
        
        # Tampilkan info sesi
        if st.session_state.last_activity:
            elapsed = time.time() - st.session_state.last_activity
            remaining = max(0, SESSION_TIMEOUT - elapsed)
            minutes, seconds = divmod(int(remaining), 60)
            st.caption(f"Sesi berakhir dalam: {minutes}:{seconds:02d}")
        
        if st.session_state.is_admin:
            st.info("🔧 Hak Akses: **Admin**")
        else:
            st.info("👤 Hak Akses: **User**")
        
        if st.button("Logout", type="secondary"):
            # Log logout
            log_login_attempt(st.session_state.username, "127.0.0.1", "Streamlit-App", True, "Logout")
            
            # Clear session
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            
            st.rerun()
    
    st.divider()
    
    # Statistik global
    if is_data_exists() and st.session_state.logged_in:
        data_db = normalize_columns(load_data())
        stats = get_statistics(data_db)
        
        st.subheader("📈 Statistik Global")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Penduduk", stats['total'])
        with col2:
            st.metric("Laki-laki", stats['laki_laki'])
        with col3:
            st.metric("Perempuan", stats['perempuan'])

# ================= FITUR PENCARIAN BANTUAN =================
if st.session_state.logged_in:
    st.sidebar.divider()
    st.sidebar.subheader("🔍 Cari Jenis Bantuan")
    
    search_name = st.sidebar.text_input("Masukkan Nama Penduduk")
    
    if search_name:
        if validate_input(search_name):
            data_db = normalize_columns(load_data())
            search_results = data_db[data_db['nama'].str.contains(search_name, case=False, na=False)]
            
            if not search_results.empty:
                st.sidebar.success(f"Ditemukan {len(search_results)} hasil")
                
                for _, row in search_results.iterrows():
                    with st.sidebar.expander(f"📌 {row['nama']}"):
                        st.write(f"**NIK:** {row.get('nik', '')}")
                        st.write(f"**Alamat:** {row.get('alamat', '')}")
                        
                        # List bantuan yang diterima
                        bantuan_cols = ['pkh', 'kks', 'pbi_jkn', 'blt', 
                                       'koperasi_merah_putih', 'pip', 
                                       'subsidi_listrik', 'lpg_3kg']
                        bantuan_diterima = []
                        
                        for col in bantuan_cols:
                            if col in row and str(row[col]).upper() == 'YA':
                                bantuan_diterima.append(col.upper())
                        
                        if bantuan_diterima:
                            st.write("**Bantuan yang diterima:**")
                            for b in bantuan_diterima:
                                st.write(f"✓ {b}")
                        else:
                            st.write("**Tidak menerima bantuan**")
            else:
                st.sidebar.warning("Nama tidak ditemukan")
        else:
            st.sidebar.error("Input tidak valid")

# ================= MAIN CONTENT BERDASARKAN LOGIN =================
if not st.session_state.logged_in:
    st.warning("Silakan login terlebih dahulu untuk mengakses sistem")
    
    # Tampilkan preview data saja jika ada
    if is_data_exists():
        data_db = normalize_columns(load_data())
        
    else:
        st.info("Database masih kosong. Login sebagai admin untuk upload data pertama kali.")
    
    st.stop()

# ================= JIKA DATABASE MASIH KOSONG =================
if not is_data_exists() and st.session_state.can_edit:
    st.warning("Database masih kosong. Silakan upload file Excel pertama kali.")
    
    uploaded_file = st.file_uploader("📥 Upload File Excel", type=["xlsx", "xls", "csv"])
    
    if uploaded_file:
        try:
            # Proses file
            success, message, df, invalid_rows = process_uploaded_file(uploaded_file)
            
            if success:
                st.success(f"✅ {message}")
                st.write(f"**Total data dalam file:** {len(df)} baris")
                
                if not invalid_rows.empty:
                    st.warning(f"⚠️ Ditemukan {len(invalid_rows)} baris dengan masalah:")
                    st.dataframe(invalid_rows)
                
                # Preview data
                with st.expander("👁️ Preview Data (20 baris pertama)"):
                    st.dataframe(df.head(20))
                
                if st.button("💾 Simpan ke Database", key="save_first", type="primary"):
                    # Simpan data
                    save_to_db(df)
                    st.success("Data berhasil disimpan ✔️")
                    st.rerun()
            else:
                st.error(f"❌ {message}")
        except Exception as e:
            st.error(f"Error membaca file: {str(e)}")

# ================= JIKA DATA SUDAH ADA =================
elif is_data_exists():
    data_db = normalize_columns(load_data())
    
    # ================= TAB UTAMA =================
    # Tambahkan tab Upload Data Massal
    tab_names = ["📋 Data Utama", "📤 Upload Data", "👪 Kartu Keluarga", "🎓 Pendidikan", 
                 "💼 Pekerjaan", "🏡 Dusun", "🧧 Bantuan Sosial",
                 "🆔 Identitas", "📊 Dashboard"]
    
    if st.session_state.is_admin:
        tab_names.append("🔧 Admin Tools")
    
    tabs = st.tabs(tab_names)
    
    with tabs[0]:  # Data Utama
        st.subheader("📋 Data Penduduk Lengkap")
        
        # Tampilkan statistik
        stats = get_statistics(data_db)
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Penduduk", stats['total'])
        with col2:
            st.metric("Laki-laki", stats['laki_laki'])
        with col3:
            st.metric("Perempuan", stats['perempuan'])
        
        if st.session_state.can_edit:
            st.info("✏️ **Mode Edit Aktif** - Data bisa diedit langsung")
            
            # Backup data lama sebelum edit
            if 'old_data' not in st.session_state:
                st.session_state.old_data = data_db.copy()
            
            edited_df = st.data_editor(
                data_db,
                num_rows="dynamic",
                use_container_width=True,
                height=500
            )
            # Hapus baris kosong / NIK tidak diisi
            edited_df = edited_df[
                edited_df["nik"].notna() &
                (edited_df["nik"].str.strip() != "") &
                (edited_df["nik"] != "-")
            ]

            # Validasi NIK sebelum simpan
            invalid_nik = edited_df[~edited_df['nik'].apply(validate_nik)]
            
            if not invalid_nik.empty:
                st.error(f"⚠️ Ditemukan {len(invalid_nik)} NIK tidak valid. Perbaiki sebelum menyimpan.")
                st.dataframe(invalid_nik[['nik', 'nama']])
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("💾 Simpan Perubahan", key="save_edit", type="primary"):
                    if invalid_nik.empty:
                        try:
                            save_to_db(edited_df)
                            st.success("Perubahan berhasil disimpan ✔️")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error menyimpan data: {str(e)}")
                    else:
                        st.error("Tidak bisa menyimpan karena ada NIK tidak valid")
            
            with col2:
                if st.button("❌ Batalkan", key="cancel_edit"):
                    if 'old_data' in st.session_state:
                        del st.session_state.old_data
                    st.rerun()
        else:
            st.info("👀 **Mode View Only** - Login sebagai admin untuk edit data")
            st.dataframe(data_db, use_container_width=True, height=500)
    
    # ================= TAB UPLOAD DATA MASAL =================
    with tabs[1]:
        st.subheader("📤 Upload Data Massal")
        st.info("Upload file Excel/CSV untuk menambah atau memperbarui data penduduk dalam jumlah besar.")
        
        # Pilihan metode upload
        col1, col2 = st.columns(2)
        with col1:
            merge_option = st.radio(
                "Pilih metode upload:",
                ["append", "update_only", "replace_all"],
                format_func=lambda x: {
                    "append": "Tambah Data Baru (abaikan duplikat)",
                    "update_only": "Perbarui Data yang Sudah Ada",
                    "replace_all": "Ganti Semua Data"
                }[x]
            )
        
        with col2:
            replace_duplicates = st.checkbox(
                "Timpa data duplikat",
                value=True,
                help="Jika dicentang, data baru akan menggantikan data lama dengan NIK yang sama"
            )
        
        # Upload file
        uploaded_file = st.file_uploader(
            "Pilih file Excel/CSV",
            type=["xlsx", "xls", "csv"],
            key="mass_upload"
        )
        
        if uploaded_file:
            # Proses file
            with st.spinner("Memproses file..."):
                success, message, df, invalid_rows = process_uploaded_file(uploaded_file)
            
            if success:
                st.success(f"✅ {message}")
                
                # Tampilkan statistik
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Data", len(df))
                with col2:
                    existing_data = load_data()
                    existing_niks = set(existing_data['nik'].astype(str))
                    new_niks = set(df['nik'].astype(str))
                    duplicate_count = len(new_niks.intersection(existing_niks))
                    st.metric("Data Duplikat", duplicate_count)
                with col3:
                    st.metric("Data Baru", len(df) - duplicate_count)
                
                # Tampilkan data invalid jika ada
                if not invalid_rows.empty:
                    st.warning(f"⚠️ Ditemukan {len(invalid_rows)} baris dengan masalah:")
                    with st.expander("Lihat Data Bermasalah"):
                        st.dataframe(invalid_rows)
                    
                    # Opsi untuk tetap upload atau tidak
                    continue_upload = st.checkbox("Tetap upload data yang valid", value=True)
                else:
                    continue_upload = True
                    st.success("✅ Semua data valid!")
                
                # Preview data
                with st.expander("👁️ Preview Data (10 baris pertama)"):
                    st.dataframe(df.head(10))
                
                # Template download
                with st.expander("📥 Download Template"):
                    st.info("Download template Excel untuk memastikan format data sesuai")
                    
                    # Buat template dataframe
                    template_data = {
                        'nik': ['1234567890123456', '2345678901234567'],
                        'nama': ['Contoh Nama 1', 'Contoh Nama 2'],
                        'jenis_kelamin': ['Laki-laki', 'Perempuan'],
                        'alamat': ['Jl. Contoh No. 1', 'Jl. Contoh No. 2'],
                        'umur': [30, 25],
                        'no_kk': ['1234567890', '2345678901'],
                        'status_keluarga': ['Kepala', 'Anggota'],
                        'pendidikan': ['SMA', 'S1'],
                        'pekerjaan': ['PNS', 'Wiraswasta'],
                        'pkh': ['Ya', 'Tidak'],
                        'kks': ['Tidak', 'Ya'],
                        'pbi_jkn': ['Ya', 'Tidak'],
                        'blt': ['Tidak', 'Ya'],
                        'koperasi_merah_putih': ['Ya', 'Tidak'],
                        'pip': ['Tidak', 'Ya'],
                        'subsidi_listrik': ['Ya', 'Tidak'],
                        'lpg_3kg': ['Tidak', 'Ya'],
                        'punya_ktp': ['Ya', 'Dalam Proses'],
                        'punya_kk': ['Ya', 'Tidak'],
                        'dusun': ['Dusun 1', 'Dusun 2']
                    }
                    
                    template_df = pd.DataFrame(template_data)
                    
                    # Convert to Excel
                    output = io.BytesIO()
                    with pd.ExcelWriter(output, engine='openpyxl') as writer:
                        template_df.to_excel(writer, index=False, sheet_name='Template')
                    
                    output.seek(0)
                    
                    st.download_button(
                        label="📥 Download Template Excel",
                        data=output,
                        file_name="template_data_penduduk.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    )
                
                # Tombol upload
                if continue_upload and st.button("🚀 Upload Data ke Database", type="primary"):
                    with st.spinner("Mengupload data..."):
                        upload_success, upload_message, count = upload_data_massal(
                            df, 
                            merge_option, 
                            replace_duplicates
                        )
                    
                    if upload_success:
                        st.success(f"✅ {upload_message}")
                        
                        # Log perubahan
                        if 'username' in st.session_state:
                            log_data_change(
                                "penduduk", 
                                "mass_upload", 
                                "mass_upload", 
                                {"count_before": len(existing_data)}, 
                                {"count_after": len(load_data())}, 
                                st.session_state.username
                            )
                        
                        # Tampilkan statistik setelah upload
                        new_data = load_data()
                        new_stats = get_statistics(new_data)
                        
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Total Data Sekarang", new_stats['total'], 
                                     delta=new_stats['total'] - stats['total'])
                        with col2:
                            st.metric("Laki-laki", new_stats['laki_laki'])
                        with col3:
                            st.metric("Perempuan", new_stats['perempuan'])
                        
                        # Tombol untuk melihat data
                        if st.button("🔄 Refresh dan Lihat Data"):
                            st.rerun()
                    else:
                        st.error(f"❌ {upload_message}")
            else:
                st.error(f"❌ {message}")
    
    # Tab lainnya tetap sama...
    with tabs[2]:  # Kartu Keluarga
        st.subheader("👪 Sistem Kartu Keluarga (KK)")
        
        # Statistik KK
        kk_stats = {
            'total_kk': data_db['no_kk'].nunique() if 'no_kk' in data_db.columns else 0,
            'kk_dengan_kepala': 0
        }
        
        if 'status_keluarga' in data_db.columns and 'no_kk' in data_db.columns:
            kk_dengan_kepala = data_db[data_db['status_keluarga'].str.contains('Kepala', case=False, na=False)]
            kk_stats['kk_dengan_kepala'] = kk_dengan_kepala['no_kk'].nunique()
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total KK", kk_stats['total_kk'])
        with col2:
            st.metric("KK dengan Kepala", kk_stats['kk_dengan_kepala'])
        
        # Fitur pencarian KK
        wajib = ["no_kk","status_keluarga"]
        for w in wajib:
            if w not in data_db.columns:
                data_db[w] = "" if w=="no_kk" else "Anggota"
        
        daftar_kk = sorted(data_db["no_kk"].dropna().unique())
        
        if len(daftar_kk)==0:
            st.warning("Belum ada data KK")
        else:
            pilih_kk = st.selectbox("Cari Nomor KK", daftar_kk, key="kk")
            data_kk = data_db[data_db["no_kk"]==pilih_kk]
            
            if len(data_kk)>0:
                kepala = data_kk[data_kk["status_keluarga"]
                                .str.contains("Kepala", case=False, na=False)]
                nama = kepala.iloc[0]["nama"] if not kepala.empty else "Belum ditandai Kepala"
                
                # Statistik anggota KK
                stats_kk = get_statistics(data_kk)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Jumlah Anggota", len(data_kk))
                with col2:
                    st.metric("Laki-laki", stats_kk['laki_laki'])
                with col3:
                    st.metric("Perempuan", stats_kk['perempuan'])
                
                st.success(f"📌 KK: {pilih_kk} | Kepala: **{nama}**")
                st.dataframe(data_kk, use_container_width=True)
    
    with tabs[3]:  # Pendidikan
        st.subheader("🎓 Pendidikan")
        
        if 'pendidikan' in data_db.columns:
            pendidikan_stats = data_db['pendidikan'].value_counts()
            
            col1, col2 = st.columns([2, 1])
            with col1:
                st.bar_chart(pendidikan_stats)
            with col2:
                st.dataframe(pendidikan_stats)
            
            daftar_pendidikan = sorted(data_db["pendidikan"].dropna().unique())
            pilih_pendidikan = st.selectbox("Pilih Pendidikan", daftar_pendidikan, key="pendidikan")
            data_pendidikan = data_db[data_db["pendidikan"]==pilih_pendidikan]
            
            stats_pend = get_statistics(data_pendidikan)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total", stats_pend['total'])
            with col2:
                st.metric("Laki-laki", stats_pend['laki_laki'])
            with col3:
                st.metric("Perempuan", stats_pend['perempuan'])
            
            st.dataframe(data_pendidikan, use_container_width=True)
    
    with tabs[4]:  # Pekerjaan
        st.subheader("💼 Pekerjaan")
        
        if 'pekerjaan' in data_db.columns:
            pekerjaan_stats = data_db['pekerjaan'].value_counts().head(10)
            
            col1, col2 = st.columns([2, 1])
            with col1:
                st.bar_chart(pekerjaan_stats)
            with col2:
                st.dataframe(pekerjaan_stats)
            
            daftar_pekerjaan = sorted(data_db["pekerjaan"].dropna().unique())
            pilih_pekerjaan = st.selectbox("Pilih Pekerjaan", daftar_pekerjaan, key="pekerjaan")
            data_pekerjaan = data_db[data_db["pekerjaan"]==pilih_pekerjaan]
            
            stats_kerja = get_statistics(data_pekerjaan)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total", stats_kerja['total'])
            with col2:
                st.metric("Laki-laki", stats_kerja['laki_laki'])
            with col3:
                st.metric("Perempuan", stats_kerja['perempuan'])
            
            st.dataframe(data_pekerjaan, use_container_width=True)
    
    with tabs[5]:  # Dusun
        st.subheader("🏡 Dusun")
        
        # Ekstrak dusun dari alamat
        data_db["alamat"] = data_db["alamat"].astype(str)
        data_db["dusun"] = data_db["alamat"].str.extract(r'(Dusun\s+[A-Za-z0-9 ]+|Dsn\.?\s*[A-Za-z0-9 ]+)', expand=False)
        data_db["dusun"] = data_db["dusun"].fillna("Tidak Terdeteksi")
        
        dusun_stats = data_db["dusun"].value_counts()
        
        col1, col2 = st.columns([2, 1])
        with col1:
            st.bar_chart(dusun_stats)
        with col2:
            st.dataframe(dusun_stats)
        
        pilih_dusun = st.selectbox("Pilih Dusun", sorted(data_db["dusun"].unique()), key="dusun")
        data_dusun = data_db[data_db["dusun"]==pilih_dusun]
        
        stats_dusun = get_statistics(data_dusun)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Penduduk", stats_dusun['total'])
        with col2:
            st.metric("Laki-laki", stats_dusun['laki_laki'])
        with col3:
            st.metric("Perempuan", stats_dusun['perempuan'])
        
        st.dataframe(data_dusun, use_container_width=True)
    
    with tabs[6]:  
        # Bantuan Sosial
        st.subheader("🧧 Data Penerima Bansos")
        
        bansos_options = {
            "PKH": "pkh",
            "KKS": "kks", 
            "PBI JKN": "pbi_jkn",
            "BLT": "blt",
            "Koperasi Merah Putih": "koperasi_merah_putih",
            "PIP": "pip",
            "Subsidi Listrik": "subsidi_listrik",
            "LPG 3kg": "lpg_3kg"
        }
        
        pilih_bansos = st.selectbox(
            "Pilih Jenis Bansos",
            list(bansos_options.keys()),
            key="bansos"
        )
        
        col_bansos = bansos_options[pilih_bansos]
        
        if col_bansos in data_db.columns:
            data_bansos = data_db[data_db[col_bansos].str.contains("Ya", case=False, na=False)]
            
            stats_bansos = get_statistics(data_bansos)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric(f"Total Penerima {pilih_bansos}", stats_bansos['total'])
            with col2:
                st.metric("Laki-laki", stats_bansos['laki_laki'])
            with col3:
                st.metric("Perempuan", stats_bansos['perempuan'])
            
            st.dataframe(data_bansos, use_container_width=True)
        else:
            st.warning(f"Kolom {col_bansos} tidak ditemukan dalam data")
    
    with tabs[7]:  # Identitas
        st.subheader("🆔 Identitas Penduduk")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.info("📝 Status Kepemilikan KTP")
            if 'punya_ktp' in data_db.columns:
                ktp_stats = data_db['punya_ktp'].value_counts()
                st.bar_chart(ktp_stats)
                
                belum_ktp = data_db[data_db["punya_ktp"].str.contains("Tidak|Belum", case=False, na=False)]
                st.metric("Belum Punya KTP", len(belum_ktp))
                if len(belum_ktp) > 0:
                    with st.expander("Daftar Belum Punya KTP"):
                        st.dataframe(belum_ktp[['nama', 'nik', 'alamat']], use_container_width=True)
        
        with col2:
            st.info("📋 Status Kepemilikan KK")
            if 'punya_kk' in data_db.columns:
                kk_stats = data_db['punya_kk'].value_counts()
                st.bar_chart(kk_stats)
                
                belum_kk = data_db[data_db["punya_kk"].str.contains("Tidak|Belum", case=False, na=False)]
                st.metric("Belum Punya KK", len(belum_kk))
                if len(belum_kk) > 0:
                    with st.expander("Daftar Belum Punya KK"):
                        st.dataframe(belum_kk[['nama', 'no_kk', 'alamat']], use_container_width=True)
        
        # Ringkasan identitas
        st.divider()
        st.subheader("📊 Ringkasan Identitas")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Data", len(data_db))
        with col2:
            punya_ktp = len(data_db[data_db["punya_ktp"].str.contains("Ya", case=False, na=False)]) if 'punya_ktp' in data_db.columns else 0
            st.metric("Punya KTP", punya_ktp)
        with col3:
            punya_kk = len(data_db[data_db["punya_kk"].str.contains("Ya", case=False, na=False)]) if 'punya_kk' in data_db.columns else 0
            st.metric("Punya KK", punya_kk)
        with col4:
            complete_id = len(data_db[
                data_db["punya_ktp"].str.contains("Ya", case=False, na=False) & 
                data_db["punya_kk"].str.contains("Ya", case=False, na=False)
            ]) if all(col in data_db.columns for col in ['punya_ktp', 'punya_kk']) else 0
            st.metric("Identitas Lengkap", complete_id)
    
    with tabs[8]:  # Dashboard
        st.subheader("📊 Dashboard Statistik")
        
        stats = get_statistics(data_db)
        
        # Statistik utama
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Penduduk", stats['total'])
        with col2:
            st.metric("Laki-laki", stats['laki_laki'])
        with col3:
            st.metric("Perempuan", stats['perempuan'])
        with col4:
            st.metric("Rasio L/P", f"{stats['laki_laki']/stats['total']*100:.1f}%" if stats['total'] > 0 else "0%")
        # Kelompok umur
        st.subheader("📈 Distribusi Kelompok Umur")
        age_data = pd.DataFrame({
            'Kelompok Umur': list(stats['age_groups'].keys()),
            'Jumlah': list(stats['age_groups'].values())
        })
        
        col1, col2 = st.columns([2, 1])
        with col1:
            st.bar_chart(age_data.set_index('Kelompok Umur'))
        with col2:
            st.dataframe(age_data, use_container_width=True)
        
        # Statistik tambahan
        st.subheader("📊 Statistik Tambahan")
        
        if 'pendidikan' in data_db.columns:
            pendidikan_stats = data_db['pendidikan'].value_counts().head(5)
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Top 5 Pendidikan:**")
                for idx, (pendidikan, count) in enumerate(pendidikan_stats.items(), 1):
                    st.write(f"{idx}. {pendidikan}: {count}")
            
        if 'pekerjaan' in data_db.columns:
            pekerjaan_stats = data_db['pekerjaan'].value_counts().head(5)
            with col2:
                st.write("**Top 5 Pekerjaan:**")
                for idx, (pekerjaan, count) in enumerate(pekerjaan_stats.items(), 1):
                    st.write(f"{idx}. {pekerjaan}: {count}")
        
        # Bantuan sosial ringkasan
        st.subheader("🧧 Ringkasan Bantuan Sosial")
        bansos_cols = ['pkh', 'kks', 'pbi_jkn', 'blt', 'koperasi_merah_putih', 'pip', 'subsidi_listrik', 'lpg_3kg']
        
        bansos_stats = {}
        for col in bansos_cols:
            if col in data_db.columns:
                count = len(data_db[data_db[col].str.contains("Ya", case=False, na=False)])
                bansos_stats[col.upper()] = count
        
        if bansos_stats:
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Jumlah Penerima Bansos:**")
                for bansos, count in list(bansos_stats.items())[:4]:
                    st.write(f"• {bansos}: {count}")
            with col2:
                st.write("**Jumlah Penerima Bansos:**")
                for bansos, count in list(bansos_stats.items())[4:]:
                    st.write(f"• {bansos}: {count}")
    
    # Admin Tools (jika ada)
    if st.session_state.is_admin and len(tabs) > 9:
        with tabs[9]:  # Admin Tools
            st.subheader("🔧 Admin Tools")
            
            tab_admin1, tab_admin2, tab_admin3 = st.tabs(["User Management", "Login Logs", "Data Audit"])
            
            with tab_admin1:
                st.subheader("Manajemen User")
                
                conn = get_connection()
                users_df = pd.read_sql("SELECT id, username, is_admin, can_edit, last_login FROM users", conn)
                conn.close()
                
                st.dataframe(users_df, use_container_width=True)
                
                col1, col2 = st.columns(2)
                with col1:
                    delete_user = st.selectbox("Pilih user untuk dihapus", 
                                             users_df['username'].tolist())
                    if st.button("🗑️ Hapus User", type="secondary"):
                        if delete_user != st.session_state.username:
                            conn = get_connection()
                            conn.execute("DELETE FROM users WHERE username = ?", (delete_user,))
                            conn.commit()
                            conn.close()
                            st.success(f"User {delete_user} berhasil dihapus")
                            st.rerun()
                        else:
                            st.error("Tidak bisa menghapus user yang sedang login")
                
                with col2:
                    reset_user = st.selectbox("Reset password user",
                                            users_df['username'].tolist())
                    new_password = st.text_input("Password baru", type="password")
                    if st.button("🔄 Reset Password"):
                        if new_password and len(new_password) >= 8:
                            conn = get_connection()
                            password_hash = hash_password(new_password)
                            conn.execute("""
                                UPDATE users 
                                SET password_hash = ?, 
                                    login_attempts = 0,
                                    locked_until = NULL
                                WHERE username = ?
                            """, (password_hash, reset_user))
                            conn.commit()
                            conn.close()
                            st.success(f"Password {reset_user} berhasil direset")
                        else:
                            st.error("Password minimal 8 karakter")
            
            with tab_admin2:
                st.subheader("Log Login")
                
                conn = get_connection()
                logs_df = pd.read_sql("""
                    SELECT username, ip_address, success, reason, timestamp 
                    FROM login_logs 
                    ORDER BY timestamp DESC 
                    LIMIT 100
                """, conn)
                conn.close()
                
                st.dataframe(logs_df, use_container_width=True)
                
                # Statistik login
                success_count = len(logs_df[logs_df['success'] == 1])
                failed_count = len(logs_df[logs_df['success'] == 0])
                
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Login Berhasil", success_count)
                with col2:
                    st.metric("Login Gagal", failed_count)
            
            with tab_admin3:
                st.subheader("Audit Trail Data")
                
                conn = get_connection()
                audit_df = pd.read_sql("""
                    SELECT table_name, record_id, change_type, 
                           changed_by, changed_at 
                    FROM data_changes 
                    ORDER BY changed_at DESC 
                    LIMIT 50
                """, conn)
                conn.close()
                
                st.dataframe(audit_df, use_container_width=True)
                
                if st.button("📥 Ekspor Log Audit"):
                    csv = audit_df.to_csv(index=False)
                    st.download_button(
                        label="Download CSV",
                        data=csv,
                        file_name="audit_log.csv",
                        mime="text/csv"
                    )

# ================= INFORMASI SISTEM =================
st.sidebar.divider()
st.sidebar.caption(f"👤 User: {st.session_state.username}")
st.sidebar.caption(f"🔐 Session: {'Aktif' if st.session_state.logged_in else 'Tidak aktif'}")
st.sidebar.caption("⚠️ Data disimpan dengan enkripsi")

# ================= PERINGATAN KEAMANAN =================
with st.sidebar.expander("⚠️ Tips Keamanan"):
    st.write("""
    1. **Jangan bagikan password** ke siapapun
    2. **Logout** setelah selesai menggunakan sistem
    3. **Ganti password** secara berkala
    4. **Hanya admin** yang bisa menambah user baru
    5. **Validasi data** sebelum menyimpan
    6. **Backup database** secara teratur
    7. **Validasi file** sebelum upload data massal
    """)
