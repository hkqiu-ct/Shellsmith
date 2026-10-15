import { useEffect, useRef, useState } from "react";
import { MessageSquarePlus } from "lucide-react";
import { AppButton, PillSegment, SettingsFieldRow, SettingsGroup, StatusMessage } from "@/components/app/common";
import { FeedbackDialog } from "@/components/app/feedback-dialog";
import { t, type Locale } from "@/lib/i18n";
import { notifyError, notifySuccess } from "@/lib/notify";
import { api, openFileDialog, saveProjectBackupDialog, type ProtectionProject, type ThemeMode } from "@/lib/tauri";

export function SettingsPage({
  locale,
  setLocale,
  themeMode,
  setThemeMode,
  telemetryEnabled,
}: {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  themeMode: ThemeMode;
  setThemeMode: (mode: ThemeMode) => void;
  /** 设置页不再展示匿名统计开关，但仍需原样回写，避免保存外观时把它重置。 */
  telemetryEnabled: boolean;
}) {
  const [selectedLocale, setSelectedLocale] = useState<Locale>(locale);
  const [selectedThemeMode, setSelectedThemeMode] = useState<ThemeMode>(themeMode);
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState<"idle" | "saved" | "failed">("idle");
  const [error, setError] = useState("");
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const [projects, setProjects] = useState<ProtectionProject[]>([]);
  const [projectBusy, setProjectBusy] = useState(false);
  useEffect(() => {
    let disposed = false;
    void api.listProtectionProjects().then((items) => { if (!disposed) setProjects(items); })
      .catch((err) => { if (!disposed) notifyError(String(err)); });
    return () => { disposed = true; };
  }, []);

  async function backupProject(project?: ProtectionProject) {
    setProjectBusy(true);
    try {
      const path = project
        ? await saveProjectBackupDialog(`${project.package_name}.protection-backup.json`)
        : await openFileDialog(t(locale, "protectionProjectRestore"), ["json"]);
      if (!path) return;
      if (project) {
        await api.exportProtectionProject(project.id, path);
        notifySuccess(t(locale, "protectionProjectSaved"));
      } else {
        await api.importProtectionProject(path);
        setProjects(await api.listProtectionProjects());
        notifySuccess(t(locale, "protectionProjectRestored"));
      }
    } catch (err) {
      notifyError(String(err));
    } finally {
      setProjectBusy(false);
    }
  }

  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    setSelectedLocale(locale);
  }, [locale]);

  useEffect(() => {
    setSelectedThemeMode(themeMode);
  }, [themeMode]);

  useEffect(() => () => {
    if (timerRef.current) {
      window.clearTimeout(timerRef.current);
    }
  }, []);

  async function persist(nextLocale: Locale, nextThemeMode: ThemeMode) {
    setSaving(true);
    setError("");
    try {
      await api.saveAppConfig({
        locale: nextLocale,
        theme_mode: nextThemeMode,
        telemetry_enabled: telemetryEnabled,
      });
      setLocale(nextLocale);
      setThemeMode(nextThemeMode);
      setStatus("saved");
      if (timerRef.current) {
        window.clearTimeout(timerRef.current);
      }
      timerRef.current = window.setTimeout(() => {
        setStatus("idle");
        timerRef.current = null;
      }, 1400);
    } catch (err) {
      const message = String(err);
      setStatus("failed");
      setError(message);
      notifyError(message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="mx-auto max-w-[920px] px-8 py-10">
      <header className="mb-9">
        <h1 className="text-[24px] font-semibold tracking-normal">{t(locale, "settingsTitle")}</h1>
      </header>

      <div className="space-y-10">
        <SettingsGroup title={t(locale, "appearance")}>
          <SettingsFieldRow label={t(locale, "theme")}>
            <div className="flex flex-wrap justify-end">
              <PillSegment
                value={selectedThemeMode}
                onChange={(value) => {
                  setSelectedThemeMode(value);
                  void persist(selectedLocale, value);
                }}
                options={[
                  { value: "system", label: t(locale, "system") },
                  { value: "light", label: t(locale, "light") },
                  { value: "dark", label: t(locale, "dark") },
                ]}
              />
            </div>
          </SettingsFieldRow>
          <SettingsFieldRow label={t(locale, "language")}>
            <div className="flex flex-wrap justify-end">
              <PillSegment
                value={selectedLocale}
                onChange={(value) => {
                  setSelectedLocale(value);
                  void persist(value, selectedThemeMode);
                }}
                options={[
                  { value: "zh", label: "中文" },
                  { value: "en", label: "English" },
                ]}
              />
            </div>
          </SettingsFieldRow>
        </SettingsGroup>
        <SettingsGroup title={t(locale, "protectionProjects")}>
          <div className="space-y-4 px-6 py-5">
            <p className="text-sm leading-6 text-muted-foreground">{t(locale, "protectionProjectsHint")}</p>
            {projects.length === 0 && <p className="text-sm text-muted-foreground">{t(locale, "protectionProjectsEmpty")}</p>}
            {projects.map((project) => (
              <div key={project.id} className="space-y-3 rounded-lg border p-4">
                <details>
                  <summary className="cursor-pointer break-all text-sm font-medium">{project.package_name}</summary>
                  <dl className="mt-3 space-y-2 text-xs">
                    <dt className="text-muted-foreground">{t(locale, "protectionProjectId")}</dt>
                    <dd className="break-all font-mono">{project.id}</dd>
                    <dt className="text-muted-foreground">{t(locale, "protectionProjectCert")}</dt>
                    <dd className="break-all font-mono">{project.certificate_sha256}</dd>
                  </dl>
                </details>
                <AppButton disabled={projectBusy} onClick={() => void backupProject(project)}>{t(locale, "protectionProjectBackup")}</AppButton>
              </div>
            ))}
            <AppButton disabled={projectBusy} onClick={() => void backupProject()}>{t(locale, "protectionProjectRestore")}</AppButton>
            <p className="text-xs leading-5 text-muted-foreground">{t(locale, "protectionProjectSecretHint")}</p>
          </div>
        </SettingsGroup>
        <SettingsGroup title={t(locale, "feedbackTitle")}>
          <div className="space-y-3 px-6 py-5">
            <p className="text-sm leading-6 text-muted-foreground">{t(locale, "feedbackEntryHint")}</p>
            <AppButton onClick={() => setFeedbackOpen(true)}>
              <MessageSquarePlus className="h-4 w-4" />
              {t(locale, "feedbackEntry")}
            </AppButton>
          </div>
        </SettingsGroup>
        {status === "saved" && (
          <StatusMessage kind="success">
            {saving ? t(locale, "saving") : t(locale, "saved")}
          </StatusMessage>
        )}
        {status === "failed" && error && <StatusMessage kind="error">{error}</StatusMessage>}
      </div>
      <FeedbackDialog locale={locale} open={feedbackOpen} onClose={() => setFeedbackOpen(false)} />
    </section>
  );
}
