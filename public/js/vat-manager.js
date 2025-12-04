/**
 * VAT Manager - Client-side script để quản lý cài đặt VAT
 * Cho phép thay đổi % VAT và hiển thị trực tiếp trên các trang
 */

class VATManager {
  constructor() {
    this.vatPercentInput = document.getElementById('vat_percent');
    this.vatPreview = document.getElementById('vat-preview');
    this.saveBtn = document.getElementById('btn-vat-save');
    this.testAmount = 1000000; // 1,000,000 VND for preview

    if (this.vatPercentInput) {
      this.init();
    }
  }

  init() {
    // Xử lý sự kiện khi thay đổi input
    this.vatPercentInput.addEventListener('input', (e) => this.updatePreview(e));
    this.vatPercentInput.addEventListener('change', (e) => this.validateInput(e));

    // Xử lý nút lưu
    if (this.saveBtn) {
      this.saveBtn.addEventListener('click', () => this.saveVAT());
    }

    // Hiển thị preview ban đầu
    this.updatePreview();
  }

  /**
   * Validate VAT input
   * - Chỉ cho phép số từ 0 đến 100
   */
  validateInput(e) {
    let value = parseInt(e.target.value, 10);

    if (isNaN(value) || value < 0) {
      value = 0;
    } else if (value > 100) {
      value = 100;
    }

    e.target.value = value;
    this.updatePreview();
  }

  /**
   * Cập nhật preview hiển thị VAT
   */
  updatePreview() {
    const vatPercent = parseInt(this.vatPercentInput.value, 10) || 0;
    const vatAmount = Math.round(this.testAmount * vatPercent / 100);
    const total = this.testAmount + vatAmount;

    if (this.vatPreview) {
      this.vatPreview.innerHTML = `
        <div class="preview-box">
          <h4>💡 Xem trước tính toán VAT</h4>
          <table class="preview-table">
            <tr>
              <td>Tạm tính:</td>
              <td><strong>${this.formatCurrency(this.testAmount)}</strong></td>
            </tr>
            <tr>
              <td>VAT (${vatPercent}%):</td>
              <td><strong style="color: var(--green);">${this.formatCurrency(vatAmount)}</strong></td>
            </tr>
            <tr style="border-top: 2px solid var(--border); font-weight: 700;">
              <td>Tổng cộng:</td>
              <td><strong>${this.formatCurrency(total)}</strong></td>
            </tr>
          </table>
          <p class="preview-note">
            (Ví dụ tính trên số tiền <strong>${this.formatCurrency(this.testAmount)}</strong>)
          </p>
        </div>
      `;
    }
  }

  /**
   * Lưu VAT setting
   */
  async saveVAT() {
    const vatPercent = parseInt(this.vatPercentInput.value, 10) || 0;

    if (vatPercent < 0 || vatPercent > 100) {
      this.showMessage('❌ VAT phải là số từ 0 đến 100%', 'error');
      return;
    }

    try {
      this.saveBtn.disabled = true;
      this.saveBtn.innerHTML = '<span>⏳ Đang lưu...</span>';

      const formData = new FormData();
      formData.append('section', 'vat');
      formData.append('vat_percent', vatPercent);
      formData.append('_csrf', document.querySelector('input[name="_csrf"]')?.value || '');

      const response = await fetch('/admin/settings/save', {
        method: 'POST',
        body: formData,
        credentials: 'same-origin'
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();

      if (data.success) {
        this.showMessage(`✅ Đã lưu VAT ${vatPercent}% thành công!`, 'success');

        // Broadcast change để update UI trên các tab khác
        if (typeof window.BroadcastChannel !== 'undefined') {
          const bc = new BroadcastChannel('vat_change');
          bc.postMessage({ type: 'VAT_UPDATED', vatPercent });
          bc.close();
        }

        // Cập nhật lại preview
        setTimeout(() => this.updatePreview(), 500);
      } else {
        this.showMessage(`❌ Lỗi: ${data.message || 'Không thể lưu VAT'}`, 'error');
      }
    } catch (error) {
      console.error('VAT save error:', error);
      this.showMessage(`❌ Lỗi: ${error.message}`, 'error');
    } finally {
      this.saveBtn.disabled = false;
      this.saveBtn.innerHTML = '<span>💾 Lưu cài đặt VAT</span>';
    }
  }

  /**
   * Hiển thị message
   */
  showMessage(message, type = 'info') {
    const messageEl = document.createElement('div');
    messageEl.className = `vat-message vat-message-${type}`;
    messageEl.innerHTML = message;
    messageEl.style.cssText = `
      padding: 12px 16px;
      margin: 12px 0;
      border-radius: 8px;
      background: ${type === 'success' ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)'};
      color: ${type === 'success' ? '#22c55e' : '#ef4444'};
      border-left: 4px solid ${type === 'success' ? '#22c55e' : '#ef4444'};
      animation: slideIn 0.3s ease;
    `;

    const container = document.querySelector('.vat-messages');
    if (container) {
      container.appendChild(messageEl);
      setTimeout(() => messageEl.remove(), 3000);
    }
  }

  /**
   * Format tiền tệ VND
   */
  formatCurrency(value) {
    return (value / 100).toLocaleString('vi-VN', {
      style: 'currency',
      currency: 'VND'
    });
  }

  /**
   * Lắng nghe thay đổi VAT từ các tab khác
   */
  static setupBroadcastListener() {
    if (typeof window.BroadcastChannel !== 'undefined') {
      try {
        const bc = new BroadcastChannel('vat_change');
        bc.onmessage = (event) => {
          if (event.data.type === 'VAT_UPDATED') {
            console.log('🔄 VAT đã được cập nhật từ tab khác:', event.data.vatPercent);
            // Có thể refresh page hoặc cập nhật UI tương ứng
            location.reload();
          }
        };
      } catch (e) {
        console.warn('BroadcastChannel không được hỗ trợ');
      }
    }
  }
}

// Khởi tạo khi document ready
document.addEventListener('DOMContentLoaded', () => {
  new VATManager();
  VATManager.setupBroadcastListener();
});

// Xuất để dùng trong các module khác nếu cần
if (typeof module !== 'undefined' && module.exports) {
  module.exports = VATManager;
}
