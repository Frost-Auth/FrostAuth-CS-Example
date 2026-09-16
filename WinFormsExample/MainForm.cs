using FrostAuth;

namespace FrostAuth.WinFormsExample;

public partial class MainForm : Form
{
    private FrostAuthClient? _app;

    public MainForm()
    {
        InitializeComponent();
        Shown += OnShown;
    }

    private async void OnShown(object? sender, EventArgs e)
    {
        _app = FrostAuthClient.Create(new FrostAuthClient.Options
        {
            Owner = "YOUR-OWNER-ID",
            Product = "YOUR-PRODUCT-ID",
            Version = "1.0.0",
            // BaseUrl = "https://api.frostauth.cc",
        });
        
        _app.Offline += (err, seconds, verified) => SafeLog($"offline {seconds}s (assertion verified: {verified}) — {err.Message}");
        _app.Invalid += err => { SafeLog($"SESSION INVALID: {err.Message}"); BeginInvoke(() => { lblStatus.Text = "Invalid licence"; lblStatus.ForeColor = Color.Firebrick; }); };
        _app.NeedsActivation += err => SafeLog("needs activation: " + err.Message);
        _app.UpdateAvailable += (current, latest) => SafeLog($"update available: {latest} (running {current})");

        try
        {
            await _app.InitAsync();
            SafeLog("connected. enter a licence key or sign in.");
        }
        catch (FrostAuthError ex)
        {
            SafeLog("init failed: " + ex.Message);
        }
    }

    private async void btnActivate_Click(object? sender, EventArgs e)
    {
        if (_app is null) return;
        btnActivate.Enabled = false;
        try
        {
            var snap = await _app.ActivateAsync(txtKey.Text.Trim());
            LogSnapshot(snap);
            lblStatus.Text = "Activated";
            lblStatus.ForeColor = Color.SeaGreen;
            _app.StartHeartbeat();
            SafeLog("heartbeat running");
        }
        catch (FrostAuthError ex)
        {
            MessageBox.Show(this, ex.Message, "Activation failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally { btnActivate.Enabled = true; }
    }

    private async void btnLogin_Click(object? sender, EventArgs e)
    {
        if (_app is null) return;
        btnLogin.Enabled = false;
        try
        {
            var snap = await _app.LoginAsync(txtUser.Text.Trim(), txtPass.Text);
            LogSnapshot(snap);
            lblStatus.Text = "Signed in";
            lblStatus.ForeColor = Color.SeaGreen;
            _app.StartHeartbeat();
            SafeLog("heartbeat running");
        }
        catch (FrostAuthError ex)
        {
            MessageBox.Show(this, ex.Message, "Sign-in failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally { btnLogin.Enabled = true; txtPass.Clear(); }
    }

    private async void btnRegister_Click(object? sender, EventArgs e)
    {
        if (_app is null) return;
        if (string.IsNullOrWhiteSpace(txtKey.Text))
        {
            MessageBox.Show(this, "Enter a licence key first.", "Register", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        btnRegister.Enabled = false;
        try
        {
            var snap = await _app.RegisterAsync(txtKey.Text.Trim(), txtUser.Text.Trim(), txtPass.Text);
            LogSnapshot(snap);
            lblStatus.Text = "Registered";
            lblStatus.ForeColor = Color.SeaGreen;
            _app.StartHeartbeat();
            SafeLog("heartbeat running");
        }
        catch (FrostAuthError ex)
        {
            MessageBox.Show(this, ex.Message, "Registration failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally { btnRegister.Enabled = true; txtPass.Clear(); }
    }

    private async void btnValidate_Click(object? sender, EventArgs e)
    {
        if (_app is null) return;
        try
        {
            var snap = await _app.ValidateAsync();
            LogSnapshot(snap);
            SafeLog("validated ok");
        }
        catch (FrostAuthError ex)
        {
            SafeLog("validate failed: " + ex.Message);
        }
    }

    private void LogSnapshot(System.Text.Json.JsonElement snap)
    {
        var user = snap.TryGetProperty("user", out var u) && u.ValueKind == System.Text.Json.JsonValueKind.String
            ? u.GetString() : null;
        BeginInvoke(() =>
        {
            lblUser.Text = "User: " + (user ?? "anonymous");
            if (snap.TryGetProperty("subscriptions", out var subs) &&
                subs.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                var i = 0;
                foreach (var sub in subs.EnumerateArray())
                    SafeLog($"subscription [{++i}]: {sub}");
            }
        });
    }

    private void SafeLog(string line)
    {
        if (InvokeRequired) BeginInvoke(() => lstLog.Items.Add(line));
        else lstLog.Items.Add(line);
    }
}
