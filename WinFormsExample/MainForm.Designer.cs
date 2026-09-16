namespace FrostAuth.WinFormsExample;

partial class MainForm
{
    private System.ComponentModel.IContainer components = null;

    private Label lblTitle;
    private Label lblStatus;
    private Label lblKey;
    private TextBox txtKey;
    private Button btnActivate;
    private Label lblUser;
    private TextBox txtUser;
    private Label lblPass;
    private TextBox txtPass;
    private Button btnLogin;
    private Button btnRegister;
    private Button btnValidate;
    private ListBox lstLog;

    protected override void Dispose(bool disposing)
    {
        if (disposing && components is not null) components.Dispose();
        base.Dispose(disposing);
    }

    private void InitializeComponent()
    {
        lblTitle = new Label();
        lblStatus = new Label();
        lblKey = new Label();
        txtKey = new TextBox();
        btnActivate = new Button();
        lblUser = new Label();
        txtUser = new TextBox();
        lblPass = new Label();
        txtPass = new TextBox();
        btnLogin = new Button();
        btnRegister = new Button();
        btnValidate = new Button();
        lstLog = new ListBox();
        SuspendLayout();

        lblTitle.AutoSize = true;
        lblTitle.Font = new Font("Segoe UI", 14F, FontStyle.Bold);
        lblTitle.Location = new Point(16, 12);
        lblTitle.Text = "FrostAuth — WinForms example";

        lblStatus.AutoSize = true;
        lblStatus.Font = new Font("Segoe UI", 10F, FontStyle.Bold);
        lblStatus.ForeColor = Color.DimGray;
        lblStatus.Location = new Point(18, 44);
        lblStatus.Text = "Not connected";

        lblKey.AutoSize = true;
        lblKey.Location = new Point(18, 80);
        lblKey.Text = "Licence key";

        txtKey.Location = new Point(110, 77);
        txtKey.Width = 240;

        btnActivate.Location = new Point(362, 75);
        btnActivate.Text = "Activate";
        btnActivate.Click += btnActivate_Click;

        lblUser.AutoSize = true;
        lblUser.Location = new Point(18, 116);
        lblUser.Text = "User";
        
        txtUser.Location = new Point(110, 113);
        txtUser.Width = 240;

        lblPass.AutoSize = true;
        lblPass.Location = new Point(18, 148);
        lblPass.Text = "Password";

        txtPass.Location = new Point(110, 145);
        txtPass.Width = 240;
        txtPass.UseSystemPasswordChar = true;

        btnLogin.Location = new Point(362, 143);
        btnLogin.Text = "Sign in";
        btnLogin.Click += btnLogin_Click;

        btnRegister.Location = new Point(452, 143);
        btnRegister.Size = new Size(110, 23);
        btnRegister.Text = "Register";
        btnRegister.Click += btnRegister_Click;

        btnValidate.Location = new Point(18, 186);
        btnValidate.Text = "Validate now";
        btnValidate.Click += btnValidate_Click;

        lstLog.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        lstLog.IntegralHeight = false;
        lstLog.Location = new Point(18, 224);
        lstLog.Size = new Size(544, 210);

        AutoScaleMode = AutoScaleMode.Font;
        ClientSize = new Size(580, 452);
        Controls.Add(lblTitle);
        Controls.Add(lblStatus);
        Controls.Add(lblKey);
        Controls.Add(txtKey);
        Controls.Add(btnActivate);
        Controls.Add(lblUser);
        Controls.Add(txtUser);
        Controls.Add(lblPass);
        Controls.Add(txtPass);
        Controls.Add(btnLogin);
        Controls.Add(btnRegister);
        Controls.Add(btnValidate);
        Controls.Add(lstLog);
        Text = "FrostAuth WinForms example";
        ResumeLayout(false);
        PerformLayout();
    }
}
