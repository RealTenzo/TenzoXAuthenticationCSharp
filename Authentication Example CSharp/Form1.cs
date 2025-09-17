using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Authentication_Example_CSharp
{
    public partial class Form1 : Form
    {
        private string appVersion = "1.0";
        private string AppName = "";
        private string Secret = "";
        private TenzoAuth auth;
        public Form1()
        {
            InitializeComponent();
            auth = new TenzoAuth(appVersion, AppName, Secret);
            if (!auth.CheckVersion())
            {
                MessageBox.Show(
                    "Your application is outdated. Please update to continue.",
                    "Update Required",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning
                );
                Environment.Exit(0);
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string username = textBox1.Text.Trim();
            string password = textBox2.Text.Trim();

            bool success = auth.Login(username, password);

            label1.Text = auth.GetLastStatusMessage();

            if (success)
            {
                MessageBox.Show(
                    $"Login successful!\nUser: {auth.GetCurrentUsername()}\nExpiry: {auth.GetExpiryDate()}",
                    "Success",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
            }
            else
            {
                MessageBox.Show(
                    "Login failed: " + auth.GetLastStatusMessage(),
                    "Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
            }
        }
        public bool isreg = false;
        private void label2_Click(object sender, EventArgs e)
        {
           if (!isreg)
            {
                isreg = true;
                label2.Text = "Login";
                panel2.Location = new Point(0, 2);
                panel1.Hide();
                panel2.Show();
            }
            else
            {
                isreg = false;
                label2.Text = "Register";
                panel1.Location = new Point(0, 2);
                panel1.Show();
                panel2.Hide();
            }   
        }

        


        private void Form1_Load(object sender, EventArgs e)
        {
            panel1.Visible = true;
            panel2.Visible = false;
            panel1.Location = new Point(0, 2);
        }

        private void button2_Click(object sender, EventArgs e)
        {
            string username = textBox3.Text;
            string password = textBox4.Text;
            string license = textBox5.Text;
            bool success = auth.Register(username, password, license);
            if (success)
            {
                MessageBox.Show(
                    $"Register successful!\nUser: {auth.GetCurrentUsername()}\nExpiry: {auth.GetExpiryDate()}",
                    "Success",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
            }
            else
            {
                MessageBox.Show(
                  "Register failed: " + auth.GetLastStatusMessage(),
                  "Error",
                  MessageBoxButtons.OK,
                  MessageBoxIcon.Error
              );
            }
        }
    }
}
