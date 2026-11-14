"use client";

import { Download, FileUp, Send, Upload } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Drawer } from "@/components/console/drawer";
import { useStepUp } from "@/components/console/step-up";
import { useAction } from "@/components/console/use-action";
import { Banner } from "@/components/ui/banner";
import { Button } from "@/components/ui/button";
import { CheckboxField } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableContainer, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useT } from "@/i18n/client";
import { needsSignIn, needsStepUp } from "@/lib/api-error";
import { formatDateTime } from "@/lib/format";
import type { UserImport, UserImportPreview, UserImportRow } from "@/lib/types";
import {
  decodeCsvFile,
  downloadText,
  IMPORT_TEMPLATE,
  importPercent,
  MAX_IMPORT_BYTES,
  toCsv,
} from "@/lib/user-import";
import {
  getUserImport,
  listUserImports,
  previewUserImport,
  resendImportInvitations,
  startUserImport,
  userImportLinks,
} from "./actions";

// Importing users from a CSV file: choose the file, read what it would do
// (nothing is written yet), start it, follow it. The import runs on the
// server: this drawer can close, and opens again on the running import. The
// link of the e-mail at the end brings the report back (?import=<id>).

/** How often a running import is asked for. It saves its totals more often than that. */
const POLL_MS = 500;
/** A longer report is in the file the admin can download. */
const ROWS_SHOWN = 100;
/** ?import=1 is the way back from a step-up; anything else is an import. */
const REOPEN = "1";

type View =
  | { step: "choose" }
  | { step: "preview"; fileName: string; csv: string; preview: UserImportPreview }
  | { step: "job"; job: UserImport };

export function ImportUsersButton({ realm, opened }: { realm: string; opened?: string }) {
  const stepUp = useStepUp();
  const router = useRouter();
  const pathname = usePathname();
  const search = useSearchParams();
  const { t } = useT();
  const [open, setOpen] = useState(!!opened);
  const close = () => {
    setOpen(false);
    if (!search.has("import")) return;
    const params = new URLSearchParams(search.toString());
    params.delete("import");
    const qs = params.toString();
    router.replace(pathname + (qs ? `?${qs}` : ""), { scroll: false });
  };
  return (
    <>
      <Button variant="secondary" onClick={() => stepUp.ensure(() => setOpen(true), `import=${REOPEN}`)}>
        <Upload />
        {t("users.import.button", "Import CSV")}
      </Button>
      {open && <ImportDrawer realm={realm} opened={opened} onClose={close} />}
    </>
  );
}

function ImportDrawer({ realm, opened, onClose }: { realm: string; opened?: string; onClose: () => void }) {
  const { run, pending } = useAction();
  const router = useRouter();
  const { t, tn } = useT();
  const [view, setView] = useState<View>({ step: "choose" });
  const [recent, setRecent] = useState<UserImport[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [sendEmail, setSendEmail] = useState(true);
  const [notify, setNotify] = useState(false);

  // Back on what is going on: the import of the link, or the running one.
  useEffect(() => {
    let gone = false;
    (async () => {
      try {
        const list = await listUserImports(realm);
        if (gone || !list.ok) return;
        setRecent(list.data.items);
        const running = list.data.items.find((j) => j.status === "running");
        if (opened && opened !== REOPEN) {
          const job = await getUserImport(realm, opened);
          if (gone) return;
          if (job.ok) setView({ step: "job", job: job.data });
          else setError(job.message);
        } else if (running) {
          setView({ step: "job", job: running });
        }
      } catch {
        // No list: the drawer still works, it only shows less.
      }
    })();
    return () => {
      gone = true;
    };
  }, [realm, opened]);

  const runningId = view.step === "job" && view.job.status === "running" ? view.job.id : null;
  useEffect(() => {
    if (!runningId) return;
    let gone = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      const r = await getUserImport(realm, runningId).catch(() => null);
      if (gone) return;
      if (r?.ok) {
        setView({ step: "job", job: r.data });
        if (r.data.status !== "running") {
          router.refresh(); // the new accounts, in the table behind
          return;
        }
      }
      timer = setTimeout(tick, POLL_MS);
    };
    timer = setTimeout(tick, POLL_MS);
    return () => {
      gone = true;
      clearTimeout(timer);
    };
  }, [realm, runningId, router]);

  const refused = (r: { message: string; error?: string; status?: number }) => {
    if (!needsStepUp(r) && !needsSignIn(r)) setError(r.message);
  };

  const choose = async (file: File) => {
    setError(null);
    if (file.size > MAX_IMPORT_BYTES) {
      setError(t("users.import.too_large", "The file is too large: 1 MB at most."));
      return;
    }
    const csv = decodeCsvFile(await file.arrayBuffer());
    if (csv === null) {
      setError(t("users.import.not_utf8", 'The file is not in UTF-8: save it again as "CSV UTF-8".'));
      return;
    }
    const r = await run(() => previewUserImport(realm, csv), {
      quiet: true,
      refresh: false,
      intent: `import=${REOPEN}`,
    });
    if (!r.ok) return refused(r);
    setSendEmail(r.data.email_enabled);
    setNotify(false);
    setView({ step: "preview", fileName: file.name, csv, preview: r.data });
  };

  const start = async () => {
    if (view.step !== "preview") return;
    setError(null);
    const { csv, fileName, preview } = view;
    const r = await run(
      () =>
        startUserImport(realm, {
          csv,
          file_name: fileName,
          send_email: preview.email_enabled && sendEmail,
          notify_when_done: preview.email_enabled && notify,
        }),
      { quiet: true, refresh: false, intent: `import=${REOPEN}` },
    );
    if (!r.ok) return refused(r);
    setView({ step: "job", job: r.data });
  };

  const openReport = async (id: string) => {
    setError(null);
    const r = await run(() => getUserImport(realm, id), { quiet: true, refresh: false });
    if (!r.ok) return refused(r);
    setView({ step: "job", job: r.data });
  };

  const downloadLinks = async (job: UserImport) => {
    setError(null);
    const r = await run(() => userImportLinks(realm, job.id), {
      quiet: true,
      refresh: false,
      intent: `import=${job.id}`,
    });
    if (!r.ok) return refused(r);
    if (r.data.links.length === 0) {
      toast.info(t("users.import.no_links", "Every account of this import already chose its password."));
      return;
    }
    downloadText(
      "activation-links.csv",
      toCsv([
        ["line", "email", "username", "activation_url", "expires_at"],
        ...r.data.links.map((l) => [l.line, l.email, l.username, l.activation_url, r.data.expires_at ?? ""]),
      ]),
    );
    toast.success(
      tn("users.import.links_done", r.data.links.length, "{count} link downloaded", "{count} links downloaded"),
    );
  };

  // The invitations that did not get through (mail server down for too
  // long, address refused): a new link, e-mailed again.
  const resendInvitations = async (job: UserImport) => {
    setError(null);
    const r = await run(() => resendImportInvitations(realm, job.id), {
      quiet: true,
      refresh: false,
      intent: `import=${job.id}`,
    });
    if (!r.ok) return refused(r);
    toast.success(
      tn("users.import.resent", r.data.sent, "{count} invitation sent again", "{count} invitations sent again"),
    );
    await openReport(job.id);
  };

  return (
    <Drawer
      open
      onClose={onClose}
      width="lg"
      title={t("users.import.title", "Import users")}
      description={t(
        "users.import.description",
        "Create accounts from a CSV file. Each one chooses its password with an activation link: a file never carries passwords.",
      )}
      footer={
        <>
          {view.step === "preview" && (
            <Button onClick={start} loading={pending} disabled={pending || view.preview.valid === 0}>
              <FileUp />
              {tn("users.import.start", view.preview.valid, "Import {count} user", "Import {count} users")}
            </Button>
          )}
          {view.step === "job" && view.job.status !== "running" && (
            <Button variant="secondary" onClick={() => setView({ step: "choose" })}>
              {t("users.import.new", "New import")}
            </Button>
          )}
          {view.step === "preview" && (
            <Button variant="secondary" onClick={() => setView({ step: "choose" })}>
              {t("users.import.other_file", "Choose another file")}
            </Button>
          )}
          <Button variant="secondary" onClick={onClose}>
            {t("common.close", "Close")}
          </Button>
        </>
      }
    >
      {error && <Banner tone="danger">{error}</Banner>}
      {view.step === "choose" && <ChooseFile pending={pending} recent={recent} onChoose={choose} onOpen={openReport} />}
      {view.step === "preview" && (
        <Preview
          fileName={view.fileName}
          preview={view.preview}
          sendEmail={sendEmail}
          notify={notify}
          onSendEmail={setSendEmail}
          onNotify={setNotify}
        />
      )}
      {view.step === "job" && (
        <Job
          job={view.job}
          pending={pending}
          onLinks={() => downloadLinks(view.job)}
          onResend={() => resendInvitations(view.job)}
        />
      )}
    </Drawer>
  );
}

function ChooseFile({
  pending,
  recent,
  onChoose,
  onOpen,
}: {
  pending: boolean;
  recent: UserImport[];
  onChoose: (f: File) => void;
  onOpen: (id: string) => void;
}) {
  const { t, locale } = useT();
  return (
    <>
      <Field
        label={t("users.import.file", "CSV file")}
        htmlFor="import-file"
        hint={t(
          "users.import.file_hint",
          "UTF-8, 1 MB and 1000 users at most. Only the email column is required. Nothing is created before you confirm.",
        )}
      >
        <Input
          id="import-file"
          type="file"
          accept=".csv,text/csv"
          className="py-2"
          disabled={pending}
          onChange={(e) => {
            const file = e.target.files?.[0];
            e.target.value = ""; // the same file can be chosen again
            if (file) onChoose(file);
          }}
        />
      </Field>
      <div className="space-y-1.5 text-[13px] text-text-secondary">
        <p>
          {t(
            "users.import.columns",
            "email, username (default: the part of the e-mail before @), groups and roles (names, separated by |). Any other column becomes a profile attribute.",
          )}
        </p>
        <p>
          {t(
            "users.import.passwords",
            "A column that looks like a password or a secret is ignored: its values are never read.",
          )}
        </p>
        <Button
          variant="link"
          onClick={() => downloadText("users-template.csv", IMPORT_TEMPLATE)}
          className="text-[13px]"
        >
          <Download />
          {t("users.import.template", "Download a template")}
        </Button>
      </div>
      {recent.length > 0 && (
        <div>
          <h3 className="mb-2 text-[13px] font-semibold text-text-secondary">
            {t("users.import.recent", "Latest imports")}
          </h3>
          <ul className="space-y-1">
            {recent.slice(0, 5).map((j) => (
              <li key={j.id}>
                <button
                  type="button"
                  onClick={() => onOpen(j.id)}
                  className="flex w-full items-center justify-between gap-3 rounded-md px-2 py-1.5 text-left text-[13px] hover:bg-surface-alt"
                >
                  <span className="min-w-0 truncate">{j.file_name || formatDateTime(j.created_at, locale)}</span>
                  <span className="shrink-0 text-text-muted">
                    {t("users.import.recent_totals", "{created} of {total}", {
                      created: j.created,
                      total: j.total,
                    })}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

function Preview({
  fileName,
  preview,
  sendEmail,
  notify,
  onSendEmail,
  onNotify,
}: {
  fileName: string;
  preview: UserImportPreview;
  sendEmail: boolean;
  notify: boolean;
  onSendEmail: (v: boolean) => void;
  onNotify: (v: boolean) => void;
}) {
  const { t, tn } = useT();
  const invalid = preview.rows.filter((r) => r.status === "failed");
  return (
    <>
      <Banner tone={preview.invalid > 0 ? "warning" : "success"}>
        <span className="font-semibold">{fileName}</span>
        <br />
        {tn("users.import.valid", preview.valid, "{count} user can be created", "{count} users can be created")}
        {preview.invalid > 0 &&
          " · " +
            tn(
              "users.import.invalid",
              preview.invalid,
              "{count} line will be skipped",
              "{count} lines will be skipped",
            )}
      </Banner>
      {preview.ignored_columns.length > 0 && (
        <Banner tone="info">
          {t("users.import.ignored", "Ignored columns, never read: {columns}", {
            columns: preview.ignored_columns.join(", "),
          })}
        </Banner>
      )}
      {preview.profile_columns.length > 0 && (
        <p className="text-[13px] text-text-secondary">
          {t("users.import.profile_columns", "Profile attributes: {columns}", {
            columns: preview.profile_columns.join(", "),
          })}
        </p>
      )}
      {invalid.length > 0 && <RefusedRows rows={invalid} fileName="import-errors.csv" />}
      {preview.email_enabled ? (
        <div className="space-y-3">
          <CheckboxField
            id="import-send"
            checked={sendEmail}
            onCheckedChange={(v) => onSendEmail(v === true)}
            label={t("users.import.send_email", "E-mail each user their activation link")}
            hint={t("users.import.send_email_hint", "Otherwise you get the links in a file when the import ends.")}
          />
          <CheckboxField
            id="import-notify"
            checked={notify}
            onCheckedChange={(v) => onNotify(v === true)}
            label={t("users.import.notify", "E-mail me when the import ends")}
            hint={t("users.import.notify_hint", "The import runs on the server: you can close this page.")}
          />
        </div>
      ) : (
        <Banner tone="neutral">
          {t(
            "users.import.no_email",
            "E-mail is not configured on the server: you get the activation links in a file when the import ends.",
          )}
        </Banner>
      )}
    </>
  );
}

function Job({
  job,
  pending,
  onLinks,
  onResend,
}: {
  job: UserImport;
  pending: boolean;
  onLinks: () => void;
  onResend: () => void;
}) {
  const { t, tn, locale } = useT();
  if (job.status === "running") {
    const percent = importPercent(job);
    return (
      <div className="space-y-3">
        <p className="text-[14px]">
          {t("users.import.running", "Importing {file}: {done} of {total} lines", {
            file: job.file_name || "CSV",
            done: job.processed,
            total: job.total,
          })}
        </p>
        <div
          role="progressbar"
          aria-valuenow={percent}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label={t("users.import.progress", "Progress of the import")}
          className="h-2 overflow-hidden rounded-full bg-neutral-soft"
        >
          <div className="h-full bg-accent transition-[width]" style={{ width: `${percent}%` }} />
        </div>
        <p className="text-[13px] text-text-secondary">
          {job.notify_when_done
            ? t("users.import.running_notify", "You can close this drawer: you will get an e-mail at the end.")
            : t("users.import.running_hint", "You can close this drawer: the import goes on, and shows here again.")}
        </p>
      </div>
    );
  }
  const interrupted = job.status === "interrupted";
  const rows = job.rows ?? [];
  const refused = rows.filter((r) => r.status === "failed");
  return (
    <>
      <Banner tone={interrupted ? "danger" : refused.length > 0 ? "warning" : "success"}>
        {interrupted
          ? t(
              "users.import.interrupted",
              "The server stopped during the import. The accounts already created are kept: import the same file again to finish, the lines already done will be refused as existing.",
            )
          : t("users.import.done", "Import finished.")}
      </Banner>
      <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 text-[14px]">
        <dt className="text-text-secondary">{t("users.import.report_file", "File")}</dt>
        <dd className="min-w-0 truncate">{job.file_name || "—"}</dd>
        <dt className="text-text-secondary">{t("users.import.report_by", "Started by")}</dt>
        <dd>
          {t("users.import.report_by_value", "{name}, {when}", {
            name: job.requested_by_name,
            when: formatDateTime(job.created_at, locale),
          })}
        </dd>
        <dt className="text-text-secondary">{t("users.import.report_created", "Accounts created")}</dt>
        <dd>{job.created}</dd>
        <dt className="text-text-secondary">{t("users.import.report_failed", "Lines refused")}</dt>
        <dd>{job.failed}</dd>
        {job.processed < job.total && (
          <>
            <dt className="text-text-secondary">{t("users.import.report_not_done", "Lines not reached")}</dt>
            <dd>{job.total - job.processed}</dd>
          </>
        )}
        {job.send_email && job.created > 0 && (
          <>
            <dt className="text-text-secondary">{t("users.import.report_invitations", "Invitations")}</dt>
            <dd>{invitationSummary(job, t)}</dd>
          </>
        )}
      </dl>
      {job.email_failed > 0 && (
        <div className="space-y-1.5">
          <Banner tone="warning">
            {tn(
              "users.import.invitations_failed",
              job.email_failed,
              "{count} invitation did not get through (mail server unavailable for too long, or address refused).",
              "{count} invitations did not get through (mail server unavailable for too long, or address refused).",
            )}
          </Banner>
          <Button variant="secondary" onClick={onResend} loading={pending} disabled={pending}>
            <Send />
            {t("users.import.resend", "Send these invitations again")}
          </Button>
          <p className="text-[12px] text-text-muted">
            {t(
              "users.import.resend_hint",
              "Each of these accounts gets a new activation link by e-mail; the previous one stops working. Accounts that chose their password since are left alone.",
            )}
          </p>
        </div>
      )}
      {job.ignored_columns.length > 0 && (
        <Banner tone="info">
          {t("users.import.ignored", "Ignored columns, never read: {columns}", {
            columns: job.ignored_columns.join(", "),
          })}
        </Banner>
      )}
      {job.without_email > 0 && (
        <div className="space-y-1.5">
          <Button variant="secondary" onClick={onLinks} loading={pending} disabled={pending}>
            <Download />
            {t("users.import.links", "Download the activation links")}
          </Button>
          <p className="text-[12px] text-text-muted">
            {t(
              "users.import.links_hint",
              "The links are not stored: each download makes new ones, and the previous ones stop working. Keep the file safe, it opens these accounts.",
            )}
          </p>
        </div>
      )}
      {refused.length > 0 && <RefusedRows rows={refused} fileName="import-errors.csv" />}
    </>
  );
}

function RefusedRows({ rows, fileName }: { rows: UserImportRow[]; fileName: string }) {
  const { t, tn } = useT();
  const shown = rows.slice(0, ROWS_SHOWN);
  const save = () =>
    downloadText(
      fileName,
      toCsv([["line", "email", "username", "error"], ...rows.map((r) => [r.line, r.email, r.username, r.error ?? ""])]),
    );
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-[13px] font-semibold text-text-secondary">
          {tn("users.import.refused", rows.length, "{count} line refused", "{count} lines refused")}
        </h3>
        <Button variant="link" onClick={save} className="text-[13px]">
          <Download />
          {t("users.import.download_errors", "Download the errors")}
        </Button>
      </div>
      <TableContainer>
        <Table className="text-[13px]">
          <TableHeader>
            <TableRow>
              <TableHead>{t("users.import.col_line", "Line")}</TableHead>
              <TableHead>{t("columns.email", "Email")}</TableHead>
              <TableHead>{t("users.import.col_error", "Reason")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {shown.map((r) => (
              <TableRow key={r.line}>
                <TableCell>{r.line}</TableCell>
                <TableCell className="max-w-48 truncate">{r.email || "—"}</TableCell>
                <TableCell>{r.error}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      {rows.length > shown.length && (
        <p className="text-[12px] text-text-muted">
          {t("users.import.more_rows", "The first {shown} are shown: the file has all of them.", {
            shown: shown.length,
          })}
        </p>
      )}
    </div>
  );
}

/** "238 sent, 2 waiting, 0 failed". */
function invitationSummary(job: UserImport, t: ReturnType<typeof useT>["t"]) {
  const rows = job.rows ?? [];
  const sent = rows.filter((r) => r.delivery === "sent").length;
  return t("users.import.invitations_value", "{sent} sent, {pending} waiting, {failed} not delivered", {
    sent,
    pending: job.email_pending,
    failed: job.email_failed,
  });
}
