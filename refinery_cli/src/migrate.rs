use std::path::Path;

use anyhow::Context;
use refinery_core::{
    config::{Config, ConfigDbType},
    find_migration_files, Migration, MigrationType, Runner, Target,
};

use crate::cli::MigrateArgs;

pub fn handle_migration_command(args: MigrateArgs) -> anyhow::Result<()> {
    run_migrations(
        &args.config,
        args.grouped,
        args.divergent,
        args.missing,
        args.fake,
        args.target,
        args.env_var.as_deref(),
        &args.path,
        &args.table_name,
        args.table_schema.as_deref(),
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_migrations(
    config_location: &Path,
    grouped: bool,
    divergent: bool,
    missing: bool,
    fake: bool,
    target: Option<u32>,
    env_var_opt: Option<&str>,
    path: &Path,
    table_name: &str,
    table_schema: Option<&str>,
) -> anyhow::Result<()> {
    let migration_files_path = find_migration_files(path, MigrationType::Sql)?;
    let mut migrations = Vec::new();
    for path in migration_files_path {
        let sql = std::fs::read_to_string(path.as_path())
            .with_context(|| format!("could not read migration file name {}", path.display()))?;

        //safe to call unwrap as find_migration_filenames returns canonical paths
        let filename = path
            .file_stem()
            .and_then(|file| file.to_os_string().into_string().ok())
            .unwrap();

        let migration = Migration::unapplied(&filename, &sql)
            .with_context(|| format!("could not read migration file name {}", path.display()))?;
        migrations.push(migration);
    }
    // `mut` is only needed by the branches that hand the `Config` itself to
    // `Runner` as the connection; the Postgres branch builds its own client.
    #[allow(unused_mut)]
    let mut config = config(config_location, env_var_opt)?;

    let target = match (fake, target) {
        (true, None) => Target::Fake,
        (false, None) => Target::Latest,
        (true, Some(version)) => Target::FakeVersion(version),
        (false, Some(version)) => Target::Version(version),
    };

    match config.db_type() {
        ConfigDbType::Mssql => {
            cfg_if::cfg_if! {
                // tiberius is an async driver so we spawn tokio runtime and run the migrations
                if #[cfg(feature = "mssql")] {
                    use tokio::runtime::Builder;

                    let runtime = Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .context("Can't start tokio runtime")?;

                    runtime.block_on(async {
                        Runner::new(&migrations)
                            .set_grouped(grouped)
                            .set_target(target)
                            .set_abort_divergent(divergent)
                            .set_abort_missing(missing)
                            .set_migration_table_name(table_name)
                            .set_migration_table_schema(table_schema.or(config.db_schema()))
                            .run_async(&mut config)
                            .await
                    })?;
                } else {
                    panic!("tried to migrate async from config for a mssql database, but mssql feature was not enabled!");
                }
            }
        }
        // Postgres does NOT go through `Runner::run(&mut config)`: that path
        // rebuilds the URL from the parsed `Config`, dropping the query string
        // (and therefore `sslmode`), and hardcodes `postgres::NoTls`. We build
        // the client ourselves from the raw DSN instead — see `crate::pg_tls`
        // and BCP-4264.
        ConfigDbType::Postgres => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "postgresql")] {
                    use refinery_core::postgres::NoTls;
                    use tokio_postgres_rustls::MakeRustlsConnect;

                    let raw_dsn = postgres_dsn(config_location, env_var_opt)?;
                    let (mut pg_config, resolved) = crate::pg_tls::prepare(&raw_dsn)?;

                    // Same precedence as before this change: in `-e <ENV_VAR>`
                    // mode `DATABASE_PASSWORD`, when set, overrides any password
                    // carried in the DSN. In `--config <toml>` mode it is NOT
                    // consulted at all — `config()`'s toml branch never touched
                    // it, and applying it there would let an unrelated exported
                    // `DATABASE_PASSWORD` override the file's `db_pass`.
                    // Setting it on the parsed config rather than splicing it
                    // into a URL also removes the URL-encoding hazard of the old
                    // rebuild.
                    if env_var_opt.is_some() {
                        if let Ok(db_pass) = std::env::var("DATABASE_PASSWORD") {
                            pg_config.password(db_pass.as_bytes());
                        }
                    }

                    let mut client = if resolved.effective == "disable" {
                        pg_config
                            .connect(NoTls)
                            .context("could not connect to database")?
                    } else {
                        let tls_config = crate::pg_tls::tls::client_config(&resolved)
                            .context("could not configure TLS for the database connection")?;
                        pg_config
                            .connect(MakeRustlsConnect::new(tls_config))
                            .context("could not connect to database over TLS")?
                    };

                    Runner::new(&migrations)
                        .set_grouped(grouped)
                        .set_abort_divergent(divergent)
                        .set_abort_missing(missing)
                        .set_target(target)
                        .set_migration_table_name(table_name)
                        // `resolved.current_schema` precedes
                        // `config.db_schema()` deliberately. In `-e <ENV_VAR>`
                        // mode the two have the SAME source — `Config`'s
                        // `TryFrom<Url>` already sets `db_schema` from the
                        // DSN's `currentSchema` — but they disagree on
                        // decoding: `Url::query_pairs()` is form-urlencoded, so
                        // a `+` becomes a space, while `dsn.rs`'s
                        // `decode_value` percent-decodes and leaves the `+`
                        // literal, matching what `tokio-postgres` does with
                        // query values. So `?currentSchema=llm+gw` must resolve
                        // to `llm+gw`, and only the DSN-derived value gets
                        // that right. In `--config <toml>` mode
                        // `resolved.current_schema` is always `None`, so
                        // `config.db_schema()` still supplies `[main]
                        // db_schema`.
                        .set_migration_table_schema(
                            table_schema
                                .or(resolved.current_schema.as_deref())
                                .or(config.db_schema()),
                        )
                        .run(&mut client)?;
                } else {
                    panic!("tried to migrate from config for a postgresql database, but the postgresql feature was not enabled!");
                }
            }
        }
        _db_type @ (ConfigDbType::Mysql | ConfigDbType::Sqlite) => {
            cfg_if::cfg_if! {
                if #[cfg(any(feature = "mysql", feature = "sqlite"))] {
                    Runner::new(&migrations)
                        .set_grouped(grouped)
                        .set_abort_divergent(divergent)
                        .set_abort_missing(missing)
                        .set_target(target)
                        .set_migration_table_name(table_name)
                        .set_migration_table_schema(table_schema.or(config.db_schema()))
                        .run(&mut config)?;
                } else {
                    panic!("tried to migrate async from config for a {:?} database, but it's matching feature was not enabled!", _db_type);
                }
            }
        }
    };

    Ok(())
}

fn config(config_location: &Path, env_var_opt: Option<&str>) -> anyhow::Result<Config> {
    if let Some(env_var) = env_var_opt {
        Config::from_env_var(env_var)
            .map(|config| {
                if let Ok(db_pass) = std::env::var("DATABASE_PASSWORD") {
                    config.set_db_pass(&db_pass)
                } else {
                    config
                }
            })
            .context("could not environment variable")
    } else {
        Config::from_file_location(config_location).context("could not parse the config file")
    }
}

/// The **raw** Postgres DSN, query string and all.
///
/// `Config::from_env_var` cannot be used for this: it parses the URL and
/// `build_db_url` then rebuilds it without the query, which is exactly the bug
/// BCP-4264 fixes. So the environment variable is read directly.
///
/// A `refinery.toml` cannot express a query string, so for the `--config` mode
/// the DSN is synthesized from the file the same way `build_db_url` would have
/// done — nothing is lost, and the Postgres path then gets TLS in that mode
/// too. The `[main] db_schema` key is picked up separately, from the parsed
/// `Config`.
#[cfg(feature = "postgresql")]
fn postgres_dsn(config_location: &Path, env_var_opt: Option<&str>) -> anyhow::Result<String> {
    if let Some(env_var) = env_var_opt {
        return std::env::var(env_var)
            .with_context(|| format!("couldn't find {} environment variable", env_var));
    }

    let file = std::fs::read_to_string(config_location)
        .with_context(|| format!("could not open config file {}", config_location.display()))?;
    let parsed: toml::Value = toml::from_str(&file).context("could not parse the config file")?;
    let main = parsed
        .get("main")
        .context("config file is missing the [main] table")?;
    let field = |name: &str| main.get(name).and_then(toml::Value::as_str);

    let mut url = String::from("postgresql://");
    let user = field("db_user");
    if let Some(user) = user {
        url.push_str(user);
    }
    if let Some(pass) = field("db_pass") {
        url.push(':');
        url.push_str(pass);
    }
    if let Some(host) = field("db_host") {
        if user.is_some() {
            url.push('@');
        }
        url.push_str(host);
    }
    if let Some(port) = field("db_port") {
        url.push(':');
        url.push_str(port);
    }
    if let Some(name) = field("db_name") {
        url.push('/');
        url.push_str(name);
    }
    Ok(url)
}
