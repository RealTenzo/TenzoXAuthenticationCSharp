using System;
using System.Windows.Forms;
using TXAAuth;

namespace CSHARP_SDK_TenzoXAuthentication
{
    public partial class Form1 : Form
    {
        public static TXA TXA = new TXA(
          name: "",
          secret: "",
          version: "1.0"
        );

        public Form1()
        {
            InitializeComponent();
            TXA.Init();
        }


        private async void button1_Click(object sender, EventArgs e)
        {
            var result = await TXA.Login(textBox1.Text, textBox2.Text);

            if (result.Success)
            {
                label1.Text = result.Message;  
            }
            else
            {
                label1.Text = result.Message;
            }
        }




        private async void button2_Click(object sender, EventArgs e)
        {
            var result = await TXA.Register(textBox1.Text, textBox2.Text, textBox3.Text);

            if (result.Success)
            {
                label1.Text = result.Message;
            }
            else
            {
                label1.Text = result.Message;
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            label1.Text = TXA.Var("AoB");
        }
    }
}
