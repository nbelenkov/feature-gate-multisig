use colored::*;

/// Centralized output formatting for consistent UI throughout the application
pub struct Output;

impl Output {
    /// Success message with green checkmark
    pub fn success(msg: &str) {
        println!("{} {}", "✅".bright_green(), msg);
    }

    /// Information message with blue info icon
    pub fn info(msg: &str) {
        println!("{} {}", "ℹ️".bright_blue(), msg);
    }

    /// Warning message with yellow warning icon
    pub fn warning(msg: &str) {
        println!("{} {}", "⚠️".bright_yellow(), msg);
    }

    /// Error message with red X icon
    pub fn error(msg: &str) {
        println!("{} {}", "❌".bright_red(), msg);
    }

    /// Header with yellow bold text
    pub fn header(msg: &str) {
        println!("{}", msg.bright_yellow().bold());
    }

    /// Field display with cyan key and white value
    pub fn field(key: &str, value: &str) {
        println!("  {}: {}", key.cyan(), value.bright_white());
    }

    /// Numbered field display (for lists)
    pub fn numbered_field(index: usize, key: &str, value: &str) {
        println!(
            "    {}: {}",
            format!("{} {}", index, key).cyan(),
            value.bright_white()
        );
    }

    /// Hint message with blue lightbulb
    pub fn hint(msg: &str) {
        println!("{} {}", "💡 Hint:".bright_blue(), msg);
    }

    /// Separator line for sections
    pub fn separator() {
        println!();
    }

    /// Configuration display with special formatting
    pub fn config_item(key: &str, value: &str) {
        println!(
            "  {}: {}",
            key.cyan(),
            if value.is_empty() || value == "None" {
                "Not configured".bright_yellow()
            } else {
                value.bright_white()
            }
        );
    }

    /// Address display with consistent formatting
    pub fn address(label: &str, addr: &str) {
        println!("  {}: {}", label.cyan(), addr.bright_white());
    }
}
