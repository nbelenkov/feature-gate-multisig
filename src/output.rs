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

    /// Subheader with cyan bold text
    pub fn subheader(msg: &str) {
        println!("{}", msg.bright_cyan().bold());
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

    /// Process step with blue arrow
    pub fn step(msg: &str) {
        println!("{} {}", "📤".bright_blue(), msg);
    }

    /// Network status with globe icon
    pub fn network(msg: &str) {
        println!("🌐 {}", msg.bright_white());
    }

    /// Search/fetch with magnifying glass
    pub fn search(msg: &str) {
        println!("🔍 {}", msg.bright_white());
    }

    /// Target/address display with target icon
    pub fn target(msg: &str) {
        println!("🎯 {}", msg.bright_white());
    }

    /// Progress with rocket icon
    pub fn progress(msg: &str) {
        println!("🚀 {}", msg);
    }

    /// Hint message with blue lightbulb
    pub fn hint(msg: &str) {
        println!("{} {}", "💡 Hint:".bright_blue(), msg);
    }

    /// Separator line for sections
    pub fn separator() {
        println!();
    }

    /// Double separator with equals signs
    pub fn section_break(title: &str) {
        println!("{}", "═".repeat(80).bright_green());
        println!("{}", title.bright_green().bold());
        println!("{}", "═".repeat(80).bright_green());
        println!();
    }

    /// Single line separator with dashes
    pub fn subsection_break(title: &str) {
        println!("{}", "─".repeat(50).bright_cyan());
        println!("{}", title.bright_cyan().bold());
        println!("{}", "─".repeat(50).bright_cyan());
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

    /// Transaction signature display
    pub fn signature(label: &str, sig: &str) {
        println!("  {}: {}", label.cyan(), sig.bright_cyan());
    }

    /// Address display with consistent formatting
    pub fn address(label: &str, addr: &str) {
        println!("  {}: {}", label.cyan(), addr.bright_white());
    }

    /// Status indicators for various states
    pub fn status_found(msg: &str) {
        println!("✅ {}", msg.bright_green());
    }

    pub fn status_not_found(msg: &str) {
        println!("❌ {}", msg.bright_red());
    }

    pub fn status_processing(msg: &str) {
        println!("⚙️ {}", msg.bright_white());
    }
}
