
#![feature(naked_functions)]
#![feature(asm)] // 添加asm特性支持

use std::{
    fs::{self, File},
    io::Read,
    os::fd::AsRawFd,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};

use dobby_rs::Address;
use jni::{objects::JObject, JNIEnv};
use lazy_static::lazy_static;
use log::{error, info, trace};
use nix::{fcntl::OFlag, sys::stat::Mode};
use zygisk_rs::{register_zygisk_module, Api, AppSpecializeArgs, Module, ServerSpecializeArgs};

static APPLICATION_SAVED: AtomicBool = AtomicBool::new(false);

lazy_static! {
    static ref JAVA_VM: *mut jni_sys::JavaVM = ptr::null_mut();
}

struct MyModule {
    api: Api,
    env: JNIEnv<'static>,
}

impl Module for MyModule {
    fn new(api: Api, env: *mut jni_sys::JNIEnv) -> Self {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("DexDumper"),
        );
        
        let env = unsafe { JNIEnv::from_raw(env.cast()).unwrap() };
        unsafe {
            if let Ok(vm) = env.get_java_vm() {
                *JAVA_VM = vm.get_java_vm_pointer() as _;
            }
        }
        
        Self { api, env }
    }

    fn pre_app_specialize(&mut self, args: &mut AppSpecializeArgs) {
        let package = match self.extract_package_name(args) {
            Ok(name) => name,
            Err(e) => {
                error!("获取包名失败: {:?}", e);
                return;
            }
        };
        
        if !self.check_package_in_list(&package) {
            self.api.set_option(zygisk_rs::ModuleOption::DlcloseModuleLibrary);
            return;
        }

        if let Err(e) = self.setup_hooks() {
            error!("初始化Hook失败: {:?}", e);
        }
    }
}

register_zygisk_module!(MyModule);

static mut OLD_OPEN_COMMON: usize = 0;

#[naked]
pub extern "C" fn new_open_common_wrapper() {
    unsafe {
        asm!(
            "sub sp, sp, 0x280",
            "stp x29, x30, [sp, #0]",
            "stp x0, x1, [sp, #0x10]",
            "stp x2, x3, [sp, #0x20]",
            "stp x4, x5, [sp, #0x30]",
            "stp x6, x7, [sp, #0x40]",
            "stp x8, x9, [sp, #0x50]",
            "mov x0, x1",
            "mov x1, x2",
            "bl {}",
            "ldp x29, x30, [sp, #0]",
            "ldp x0, x1, [sp, #0x10]",
            "ldp x2, x3, [sp, #0x20]",
            "ldp x4, x5, [sp, #0x30]",
            "ldp x6, x7, [sp, #0x40]",
            "ldp x8, x9, [sp, #0x50]",
            "add sp, sp, 0x280",
            "adrp x16, {}",
            "ldr x16, [x16, #:lo12:{0}]",
            "br x16",
            sym new_open_common,
            sym OLD_OPEN_COMMON,
            options(noreturn)
        );
    }
}

extern "C" fn new_open_common(base: usize, size: usize) {
    let package = match get_process_name() {
        Ok(name) => name,
        Err(e) => {
            error!("获取进程名失败: {:?}", e);
            return;
        }
    };

    if let Err(e) = save_dex(base, size, &package) {
        error!("DEX保存失败: {:?}", e);
    }
    
    if !APPLICATION_SAVED.load(Ordering::Relaxed) {
        if let Err(e) = save_application_info(&package) {
            error!("应用信息保存失败: {:?}", e);
        }
        APPLICATION_SAVED.store(true, Ordering::Relaxed);
    }
}

fn save_dex(base: usize, size: usize, package: &str) -> anyhow::Result<()> {
    let dex_data = unsafe { std::slice::from_raw_parts(base as *const u8, size) };
    let dir = format!("/data/data/{}/dexes", package);
    fs::create_dir_all(&dir)?;

    let mut hasher = crc32fast::Hasher::new();
    hasher.update(dex_data);
    let file_name = format!("{}/{:08x}.dex", dir, hasher.finalize());
    fs::write(file_name, dex_data)?;
    Ok(())
}

fn save_application_info(package: &str) -> anyhow::Result<()> {
    let env = unsafe { get_jni_env()? };
    let class_name = get_application_class(&env)?;
    
    let path = format!("/data/data/{}/dexes/Application.txt", package);
    fs::write(path, class_name)?;
    Ok(())
}

unsafe fn get_jni_env() -> anyhow::Result<JNIEnv<'static>> {
    let mut env = ptr::null_mut();
    let status = (**JAVA_VM).GetEnv(JAVA_VM, &mut env, jni_sys::JNI_VERSION_1_6);
    
    if status == jni_sys::JNI_OK {
        Ok(JNIEnv::from_raw(env.cast())?)
    } else {
        let status = (**JAVA_VM).AttachCurrentThread(JAVA_VM, &mut env, ptr::null_mut());
        if status == jni_sys::JNI_OK {
            Ok(JNIEnv::from_raw(env.cast())?)
        } else {
            Err(anyhow::anyhow!("JNI环境初始化失败"))
        }
    }
}

fn get_application_class(env: &JNIEnv) -> anyhow::Result<String> {
    let activity_thread = env.find_class("android/app/ActivityThread")?;
    let current_thread = env.call_static_method(
        activity_thread,
        "currentActivityThread",
        "()Landroid/app/ActivityThread;",
        &[],
    )?.l()?;

    let app_bind_data: JObject = env.get_field(current_thread, "mBoundApplication", "Landroid/app/ActivityThread$AppBindData;")?.l()?;
    let app_info: JObject = env.get_field(app_bind_data, "appInfo", "Landroid/content/pm/ApplicationInfo;")?.l()?;
    let class_name: JObject = env.get_field(app_info, "className", "Ljava/lang/String;")?.l()?;

    Ok(env.get_string(class_name.into())?.to_string_lossy().into_owned())
}

impl MyModule {
    fn extract_package_name(&self, args: &AppSpecializeArgs) -> anyhow::Result<String> {
        let jstr = unsafe { (args.nice_name as *mut jni_sys::jstring).as_ref().unwrap() };
        Ok(self.env.get_string(jstr)?.to_string_lossy().into_owned())
    }

    fn check_package_in_list(&self, package: &str) -> bool {
        let Ok(mut file) = File::open("list.txt") else { return false };
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap_or(0) > 0 && 
        content.lines().any(|line| line.trim() == package)
    }

    fn setup_hooks(&self) -> anyhow::Result<()> {
        let symbol = "_ZN3art13DexFileLoader10OpenCommonEPKhmRKNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEEjbbPS9_PNS_22DexFileLoaderErrorCodeE";
        
        let address = dobby_rs::resolve_symbol("libdexfile.so", symbol)
            .ok_or_else(|| anyhow::anyhow!("符号解析失败"))?;

        unsafe {
            OLD_OPEN_COMMON = dobby_rs::hook(address, new_open_common_wrapper as Address)? as usize;
        }
        Ok(())
    }
}

fn get_process_name() -> anyhow::Result<String> {
    let mut cmdline = fs::read_to_string("/proc/self/cmdline")?;
    if let Some(pos) = cmdline.find('\0') {
        cmdline.truncate(pos);
    }
    Ok(cmdline)
}
