import React, { useState } from 'react';
import {
  X,
  Key,
  Plus,
  Trash2,
  Check,
  AlertCircle,
  Lock,
} from 'lucide-react';
import { CloudflareAccount, CloudflareZone } from '../types/security';

interface AccountSettingsModalProps {
  accounts: CloudflareAccount[];
  zones: CloudflareZone[];
  onClose: () => void;
  onAddAccount: (name: string, token: string) => void;
  onDeleteAccount: (id: string) => void;
}

export const AccountSettingsModal: React.FC<AccountSettingsModalProps> = ({
  accounts,
  zones,
  onClose,
  onAddAccount,
  onDeleteAccount,
}) => {
  const [newAccountName, setNewAccountName] = useState('');
  const [newApiToken, setNewApiToken] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newAccountName.trim() || !newApiToken.trim()) {
      setErrorMsg('Account name and Cloudflare API Token are required.');
      return;
    }

    if (newApiToken.length < 16) {
      setErrorMsg('Cloudflare API Token must be at least 16 characters.');
      return;
    }

    onAddAccount(newAccountName.trim(), newApiToken.trim());
    setNewAccountName('');
    setNewApiToken('');
    setErrorMsg('');
    setSuccessMsg('Account successfully connected and token securely stored!');

    setTimeout(() => setSuccessMsg(''), 3000);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-[#121215] border border-[#27272f] w-full max-w-2xl rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-5 border-b border-[#27272f] bg-[#16161b] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-blue-500/15 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <Key className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-zinc-100">
                Cloudflare Accounts & Token Credentials
              </h2>
              <p className="text-xs text-zinc-400">
                Multi-account API connections with zero-leakage token encryption
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-sm">
          {/* Security Banner */}
          <div className="flex items-start gap-3 p-3.5 bg-blue-500/10 border border-blue-500/20 rounded-lg text-xs text-blue-300">
            <Lock className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
            <div>
              <strong className="block font-semibold mb-0.5 text-blue-200">
                Credential Security & Principle of Least Privilege
              </strong>
              <span>
                Tokens are stored encrypted with AES-GCM and never transmitted to third parties or logged in plaintext. EdgeWatch requires scoped permissions: <code>Zone.WAF:Edit</code> and <code>Zone.Analytics:Read</code>.
              </span>
            </div>
          </div>

          {/* Connected Accounts List */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
              Connected Cloudflare Accounts ({accounts.length})
            </h3>

            <div className="space-y-2">
              {accounts.map((acc) => {
                const accZones = zones.filter((z) => z.accountId === acc.id);
                return (
                  <div
                    key={acc.id}
                    className="p-4 bg-[#18181c] border border-zinc-800 rounded-lg flex items-center justify-between text-xs"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-zinc-100 text-sm">{acc.name}</span>
                        <span className="bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded text-[10px] font-semibold flex items-center gap-1">
                          <Check className="w-3 h-3" /> Verified
                        </span>
                      </div>
                      <div className="font-mono text-zinc-400">
                        Token: <span className="text-zinc-300">{acc.maskedToken}</span>
                      </div>
                      <div className="text-zinc-500">
                        Connected Zones ({accZones.length}):{' '}
                        <span className="text-zinc-400 font-mono">
                          {accZones.map((z) => z.name).join(', ')}
                        </span>
                      </div>
                    </div>

                    {accounts.length > 1 && (
                      <button
                        onClick={() => onDeleteAccount(acc.id)}
                        className="p-2 text-zinc-500 hover:text-red-400 hover:bg-zinc-800 rounded transition cursor-pointer"
                        title="Disconnect Account"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Add Account Form */}
          <form onSubmit={handleSave} className="p-4 bg-[#15151a] border border-zinc-800/80 rounded-lg space-y-3">
            <h4 className="text-xs font-semibold text-zinc-300 uppercase tracking-wider flex items-center gap-1.5">
              <Plus className="w-3.5 h-3.5 text-blue-400" /> Connect Additional Cloudflare Account
            </h4>

            {errorMsg && (
              <div className="p-2.5 bg-red-500/15 border border-red-500/30 rounded text-red-300 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{errorMsg}</span>
              </div>
            )}

            {successMsg && (
              <div className="p-2.5 bg-emerald-500/15 border border-emerald-500/30 rounded text-emerald-300 text-xs flex items-center gap-2">
                <Check className="w-4 h-4 shrink-0" />
                <span>{successMsg}</span>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div>
                <label className="text-zinc-400 block mb-1">Account Display Name</label>
                <input
                  type="text"
                  value={newAccountName}
                  onChange={(e) => setNewAccountName(e.target.value)}
                  placeholder="e.g. Acme EMEA Staging"
                  className="w-full bg-[#18181c] border border-zinc-700 text-zinc-100 rounded p-2 text-xs focus:ring-1 focus:ring-blue-500 outline-none"
                />
              </div>

              <div>
                <label className="text-zinc-400 block mb-1">Scoped API Token</label>
                <input
                  type="password"
                  value={newApiToken}
                  onChange={(e) => setNewApiToken(e.target.value)}
                  placeholder="cf_tok_••••••••••••••••"
                  className="w-full bg-[#18181c] border border-zinc-700 text-zinc-100 rounded p-2 text-xs font-mono focus:ring-1 focus:ring-blue-500 outline-none"
                />
              </div>
            </div>

            <button
              type="submit"
              className="mt-2 w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold flex items-center justify-center gap-1.5 transition cursor-pointer shadow-sm"
            >
              <Key className="w-3.5 h-3.5" /> Encrypt & Connect Account
            </button>
          </form>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-[#27272f] bg-[#16161b] flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 rounded-lg text-xs font-medium transition cursor-pointer"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
