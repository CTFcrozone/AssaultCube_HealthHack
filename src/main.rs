use std::{rc::Rc, cell::RefCell, thread,time,mem,ptr,ffi::{CStr,c_void}};
use fltk::{app, window::Window, input::{Input, SecretInput}, frame::Frame, enums::{Align, Color, Event}, button::Button, prelude::*, *};
use fltk_theme::{ColorTheme, color_themes};
use winapi::um::memoryapi::{ReadProcessMemory,WriteProcessMemory};
use winapi::um::processthreadsapi::OpenProcess;
use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Module32First, Module32Next, MODULEENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32};
use winapi::um::handleapi::{CloseHandle,INVALID_HANDLE_VALUE};
use winapi::shared::minwindef::DWORD;
use libc::uintptr_t;
use winapi::um::winnt::{PROCESS_ALL_ACCESS, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_VM_OPERATION};
use windows::Win32::Foundation::HWND;
use mysql::*;
use mysql::prelude::*;
use thiserror::Error;

const BTN_MAIN_COLOR: Color = Color::from_rgb(0, 150, 255);
const BTN_SECONDARY_COLOR: Color = Color::from_rgb(111,143,175);

pub struct Mem;
pub struct Game;

#[derive(Debug, Error)]
enum HwidErr {
    #[error("No HWID found")]
    NotFound
}

#[allow(dead_code)]
#[derive(FromRow)]
struct Account {
    id: i32,
    username: String,
    password: String,
    hwid: String,
}

impl Account {
    fn get_acc(username: &String, password: &String, hwid: &String, conn: &mut PooledConn) -> Result<Option<Account>, mysql::Error> {
        let sql = "SELECT id, username, password, hwid FROM auth WHERE username = :username AND password = :password AND hwid= :hwid";
        let params = params! {
            "username" => username,
            "password" => password,
            "hwid" => hwid,
        };
        let stmt = conn.prep(sql)?;
        let result: Result<Vec<Account>,_> = conn.exec_map(stmt,params,|(id,username,password,hwid)|{
            Account{id,username,password,hwid}
        });
        match result {
            Ok(mut accounts) => {
                if accounts.is_empty(){
                    Ok(None)
                } else {
                    Ok(Some(accounts.pop().unwrap()))
                }
            }
            Err(err) => Err(err)
        }
    }

    fn get_hwid() -> Result<String, HwidErr>{
        let pkg = winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags("Software\\Microsoft\\Cryptography", KEY_QUERY_VALUE)
            .map_err(|_| HwidErr::NotFound)?;
        let id: String = pkg.get_value("MachineGuid").map_err(|_| HwidErr::NotFound)?;
        Ok(id)
    }

    fn auth_and_run(username: &String, password: &String, conn: Rc<RefCell<PooledConn>>){
        match Account::get_hwid() {
            Ok(hwid) => {
                match Account::get_acc(&username, &password, &hwid, &mut conn.borrow_mut()) {
                    Ok(Some(account)) => {
                        dialog::alert_default(&format!("Successfully authenticated as user '{}'.", account.username));
                        app::quit();
                        loop{
                            println!("--------------------------");
                            Game::read_health();
                            Game::write_health();
                            thread::sleep(time::Duration::from_secs(2));
                        }
                    }
                    Ok(None) => {
                        dialog::alert_default("Authentication error: No account found for the given credentials.");
                    }
                    Err(err) => {
                        dialog::alert_default(&format!("Error occurred while authenticating: {}", err));
                    }
                }
            }
            Err(err) => {
                dialog::alert_default(&format!("Error occurred while fetching HWID: {}", err));
            }
        }
    }
}

impl Mem {
    pub fn get_pointer_address(hwnd: HWND, game_base_addr: uintptr_t, address: uintptr_t, offsets: &Vec<u32>) -> uintptr_t{
        let mut pid: u32 = 0;
        unsafe {
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            let phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if phandle.is_null() {
                panic!("Failed to open process");
            }
            let mut offset_null = 0;
            ReadProcessMemory(phandle, (game_base_addr + address) as *const c_void, &mut offset_null as *mut u32 as *mut c_void, mem::size_of::<u32>(), ptr::null_mut());
            let mut pointer_address = offset_null;
            for i in 0..offsets.len() - 1 {
                ReadProcessMemory(phandle, (pointer_address + offsets[i]) as *const c_void, &mut pointer_address as *mut u32 as *mut c_void, mem::size_of::<u32>(), ptr::null_mut());
            }
            pointer_address += offsets[offsets.len() - 1];
            pointer_address as uintptr_t
        }
    }
    pub fn get_module_base_address(dw_proc_id: DWORD, sz_module_name: &str) -> uintptr_t {
        let mut module_base_address: uintptr_t = 0;
        let h_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dw_proc_id) };
        if h_snapshot != INVALID_HANDLE_VALUE {
            let mut module_entry32: MODULEENTRY32 = unsafe { mem::zeroed() };
            module_entry32.dwSize = mem::size_of::<MODULEENTRY32>() as DWORD;
            if unsafe { Module32First(h_snapshot, &mut module_entry32) } != 0 {
                loop {
                    let module_name = unsafe { CStr::from_ptr(module_entry32.szModule.as_ptr())};
                    if module_name.to_str().unwrap().eq_ignore_ascii_case(sz_module_name) {
                        module_base_address = module_entry32.modBaseAddr as uintptr_t;
                        break;
                    }
                    if unsafe { Module32Next(h_snapshot, &mut module_entry32) } == 0 {
                        break;
                    }
                }
            }
            unsafe { CloseHandle(h_snapshot) };
        }
        module_base_address
    }
}

impl Game {
    fn read_health() {
        let window_name = windows::core::s!("AssaultCube");
        let game = unsafe { windows::Win32::UI::WindowsAndMessaging::FindWindowA(None, window_name) };
        let mut pid = 0;
        unsafe { GetWindowThreadProcessId(game, Some(&mut pid)) };
        let processhandle = unsafe { OpenProcess(PROCESS_VM_READ, 0, pid) };
        if processhandle.is_null() {
            let err = unsafe{windows::Win32::Foundation::GetLastError() };
            eprintln!("Error opening process: {:?}", err);
            return;
        }

        let game_name = "ac_client.exe";
        let game_base_address: uintptr_t = Mem::get_module_base_address(pid, game_name);
        println!("Game base address: {}", game_base_address);

        let offset_game_to_base_address: uintptr_t = 0x0017E0A8;
        let points_offsets = vec![0xEC];
        let addr = Mem::get_pointer_address(game, game_base_address, offset_game_to_base_address, &points_offsets);
        println!("Target address: {}", addr);

        let mut health: i32 = 0;
        let read_result = unsafe {
            ReadProcessMemory(
                processhandle,
                addr as *const c_void,
                std::ptr::addr_of_mut!(health) as *mut c_void,
                std::mem::size_of::<i32>(),
                std::ptr::null_mut(),
            )
        };
        if read_result == 0 {
            let err = unsafe{ windows::Win32::Foundation::GetLastError() };
            eprintln!("Error reading process memory: {:?}", err);
        } else {
            println!("Health value: {}", health);
        }
        unsafe { CloseHandle(processhandle) };
    }
    fn write_health() {
        let window_name = windows::core::s!("AssaultCube");
        let game = unsafe { windows::Win32::UI::WindowsAndMessaging::FindWindowA(None, window_name) };
        let mut pid = 0;
        unsafe { GetWindowThreadProcessId(game, Some(&mut pid)) };
        let processhandle = unsafe { OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, pid) };
        if processhandle.is_null() {
            let err = unsafe{windows::Win32::Foundation::GetLastError()};
            println!("Error opening process: {:?}", err);
            return;
        }
        let game_name = "ac_client.exe";
        let game_base_address: uintptr_t = Mem::get_module_base_address(pid, game_name);

        let offset_game_to_base_address: uintptr_t = 0x0017E0A8;
        let points_offsets = vec![0xEC];
        let addr = Mem::get_pointer_address(game, game_base_address, offset_game_to_base_address, &points_offsets);

        let mut health: i32 = 1782;
        let write_result = unsafe {
            WriteProcessMemory(
                processhandle,
                addr as *mut c_void,
                std::ptr::addr_of_mut!(health) as *const c_void,
                std::mem::size_of::<i32>(),
                std::ptr::null_mut(),
            )
        };
        if write_result == 0 {
            let err = unsafe{windows::Win32::Foundation::GetLastError()};
            eprintln!("Error writing process memory: {:?}", err);
        } else {
            println!("Successfully updated the health value");
        }
        unsafe { CloseHandle(processhandle) };
    }

}

#[allow(unused_variables)]
fn build_ui(conn: Rc<RefCell<PooledConn>>) {
    let mut flex = group::Flex::default().column().with_size(250, 250).center_of_parent();
    let label_main = Frame::default().with_label("Authentication").set_label_size(32);
    let uname_label = Frame::default().with_label("Username: ");
    let username = Input::default().with_align(Align::Center);
    let pass_label = Frame::default().with_label("Password: ");
    let password = SecretInput::default().with_align(Align::Center);
    let spacer = Frame::default();

    let mut btn = Button::default().with_label("Login");
    btn.set_color(BTN_MAIN_COLOR);
    btn.set_selection_color(BTN_SECONDARY_COLOR);
    btn.set_label_color(Color::Black);

    flex.fixed(&username, 20);
    flex.fixed(&password, 20);
    flex.fixed(&spacer,10);
    flex.end();

    btn.set_callback(move |btn| {
        if username.value().is_empty() || password.value().is_empty() {
            dialog::alert_default("Please enter all needed details");
        } else {
            Account::auth_and_run(&username.value(), &password.value(), Rc::clone(&conn));
        }
    });

    btn.handle(move |btn, event| match event{
        Event::Enter => {
            btn.set_color(BTN_SECONDARY_COLOR);
            btn.redraw();
            true
        }
        Event::Leave => {
            btn.set_color(BTN_MAIN_COLOR);
            btn.redraw();
            true
        }
        _ => false,
    });

}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let url = "mysql://StuxRot:evilcore[1337]@localhost:3306/app";
    let pool = Pool::new(url)?;
    let conn = pool.get_conn()?;
    let conn_rc = Rc::new(RefCell::new(conn));
    let mut win = Window::default().with_size(400, 400).with_label("AuthClient").center_screen();
    let application = app::App::default().with_scheme(app::Scheme::Gtk);
    let theme = ColorTheme::from_colormap(color_themes::DARK_THEME);
    theme.apply();
    build_ui(Rc::clone(&conn_rc));
    win.end();
    win.show();
    application.run().unwrap();
    Ok(())
}
