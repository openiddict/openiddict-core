namespace OpenIddict.Sandbox.WinForms.Client
{
    partial class MainForm
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.LocalLogin = new System.Windows.Forms.Button();
            this.TwitterLogin = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // LocalLogin
            // 
            this.LocalLogin.Location = new System.Drawing.Point(258, 93);
            this.LocalLogin.Name = "LocalLogin";
            this.LocalLogin.Size = new System.Drawing.Size(283, 83);
            this.LocalLogin.TabIndex = 0;
            this.LocalLogin.Text = "Log in using the local server";
            this.LocalLogin.UseVisualStyleBackColor = true;
            this.LocalLogin.Click += new System.EventHandler(this.LocalLoginButton_Click);
            // 
            // TwitterLogin
            // 
            this.TwitterLogin.Location = new System.Drawing.Point(258, 258);
            this.TwitterLogin.Name = "TwitterLogin";
            this.TwitterLogin.Size = new System.Drawing.Size(283, 83);
            this.TwitterLogin.TabIndex = 1;
            this.TwitterLogin.Text = "Log in using Twitter";
            this.TwitterLogin.UseVisualStyleBackColor = true;
            this.TwitterLogin.Click += new System.EventHandler(this.TwitterLoginButton_Click);
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.TwitterLogin);
            this.Controls.Add(this.LocalLogin);
            this.Name = "MainForm";
            this.Text = "OpenIddict WinForms client";
            this.ResumeLayout(false);

        }

        #endregion

        private Button LocalLogin;
        private Button TwitterLogin;
    }
}