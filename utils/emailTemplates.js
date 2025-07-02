// Function to generate the welcome email for Employers (Schools/Colleges)
export const getEmployerWelcomeTemplate = (name) => {
  // Safety check to prevent errors if name is missing
  const firstName = name ? name.split(" ")[0] : "Employer";
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Welcome to TeacherJob.in</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #374151; }
        .container { max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #e5e7eb; border-radius: 8px; background-color: #ffffff; }
        .header { text-align: center; border-bottom: 1px solid #e5e7eb; padding-bottom: 15px; margin-bottom: 20px; }
        .header h1 { color: #4F46E5; font-size: 24px; margin: 0; } /* <-- NEW COLOR */
        .content h2 { color: #111827; font-size: 20px; }
        .content p { font-size: 16px; }
        .terms-list { list-style-type: none; padding-left: 0; }
        .terms-list li { margin-bottom: 10px; font-size: 15px; display: flex; align-items: flex-start; }
        .terms-list .icon { color: #4F46E5; margin-right: 10px; font-size: 20px; line-height: 1.2; } /* <-- NEW COLOR */
        .footer { text-align: center; margin-top: 25px; font-size: 14px; color: #6b7280; }
        .button { display: inline-block; padding: 12px 24px; margin-top: 20px; background-color: #4F46E5; color: #ffffff; text-decoration: none; border-radius: 5px; font-weight: bold; } /* <-- NEW COLOR */
        a { color: #4F46E5; } /* <-- NEW COLOR */
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🏫 Welcome to TeacherJob.in — For Employers</h1>
        </div>
        <div class="content">
          <h2>Hi ${firstName},</h2>
          <p>Welcome to <strong>TeacherJob.in</strong>, India's most transparent and dedicated hiring platform for schools, colleges, and coaching centers. We’re here to simplify your hiring journey with zero hassle.</p>
          <p>We’re proud to offer <strong>100% free recruitment support</strong> for institutions looking to hire qualified teachers, professors, and support staff across the country.</p>
          
          <h2>📜 Employer Terms & Conditions (Summary)</h2>
          <p>To ensure smooth, fair, and transparent hiring, we request all employers to follow these basic terms:</p>
          <ul class="terms-list">
            <li><span class="icon">✅</span>No upfront fee required — All job postings and candidate shortlisting are 100% free.</li>
            <li><span class="icon">✅</span>Interviews & offers must be routed through our platform for transparency and coordination.</li>
            <li><span class="icon">✅</span>Job offers should be made in writing and shared with both candidate and our team.</li>
            <li><span class="icon">✅</span>Our job security policy covers 6 months — If a candidate leaves early or doesn’t join, we provide a free replacement.</li>
            <li><span class="icon">✅</span>All communication must be professional and free of bias, harassment, or discrimination.</li>
            <li><span class="icon">✅</span>Institutions agree to follow standard labor laws and ethical onboarding practices.</li>
          </ul>
          
          <p>For full legal terms or onboarding documentation, feel free to contact us at <a href="mailto:employers@teacherjob.in">employers@teacherjob.in</a>.</p>

          <a href="${process.env.FRONTEND_URL}/dashboard" class="button">Go to Your Dashboard</a>
        </div>
        <div class="footer">
          <p>Warm regards,<br>Team TeacherJob.in</p>
          <p><small>A Brand by MentisGate Learning Pvt. Ltd.</small></p>
        </div>
      </div>
    </body>
    </html>
  `;
};

// Function to generate the welcome email for Employees (Teachers/Candidates)
export const getEmployeeWelcomeTemplate = (name) => {
  // Safety check to prevent errors if name is missing
  const firstName = name ? name.split(" ")[0] : "there";
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Welcome to TeacherJob.in</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #374151; }
        .container { max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #e5e7eb; border-radius: 8px; background-color: #ffffff; }
        .header { text-align: center; border-bottom: 1px solid #e5e7eb; padding-bottom: 15px; margin-bottom: 20px; }
        .header h1 { color: #F97316; font-size: 24px; margin: 0; } /* <-- NEW COLOR */
        .content h2 { color: #111827; font-size: 20px; }
        .content p { font-size: 16px; }
        .steps-list { list-style-type: none; padding-left: 0; }
        .steps-list li { margin-bottom: 12px; font-size: 15px; display: flex; align-items: flex-start; }
        .steps-list .icon { color: #F97316; margin-right: 10px; font-size: 20px; line-height: 1.2; } /* <-- NEW COLOR */
        .footer { text-align: center; margin-top: 25px; font-size: 14px; color: #6b7280; }
        .button { display: inline-block; padding: 12px 24px; margin-top: 20px; background-color: #F97316; color: #ffffff; text-decoration: none; border-radius: 5px; font-weight: bold; } /* <-- NEW COLOR */
        a { color: #F97316; } /* <-- NEW COLOR */
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>✅ Welcome to TeacherJob.in – Let’s Build Your Career!</h1>
        </div>
        <div class="content">
          <h2>Hi ${firstName},</h2>
          <p>Welcome to <strong>TeacherJob.in</strong>, India’s most trusted platform for verified teaching and education jobs. We’re excited to support your journey as an educator or school professional!</p>
          <p>Our mission is to help you find the right job, at the right place, with complete transparency. And yes — all this without charging you any upfront fee.</p>

          <h2>🌟 Here’s what happens next:</h2>
          <ul class="steps-list">
            <li><span class="icon">✅</span>Our team reviews your profile and matches you with verified openings.</li>
            <li><span class="icon">✅</span>If shortlisted, we will schedule an interview and help you prepare.</li>
            <li><span class="icon">✅</span>Once selected, we assist with onboarding, joining coordination, and even travel guidance.</li>
            <li><span class="icon">✅</span>You also get access to our 6-month job security policy and a welcome gift upon joining!</li>
          </ul>

          <p><strong>Make the most of your profile by keeping it complete and updated!</strong></p>
          
          <a href="${process.env.FRONTEND_URL}/my-profile" class="button">Complete Your Profile</a>
        </div>
        <div class="footer">
          <p>Let’s build your career, together.<br>Team TeacherJob.in</p>
          <p><small>A Brand by MentisGate Learning Pvt. Ltd.</small></p>
        </div>
      </div>
    </body>
    </html>
  `;
};
