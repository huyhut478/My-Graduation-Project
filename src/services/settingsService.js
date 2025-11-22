import { pool } from '../config/database.js';

async function getSetting(key, def = '') {
  try {
    const result = await pool.query('SELECT value FROM settings WHERE key = $1', [key]);
    if (result.rows.length > 0 && result.rows[0].value !== null && result.rows[0].value !== undefined) {
      return String(result.rows[0].value).trim();
    }
    return String(def).trim();
  } catch (error) {
    console.error(`Error getting setting ${key}:`, error);
    return String(def).trim();
  }
}

async function setSetting(key, value) {
  try {
    await pool.query(
      'INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value',
      [key, value]
    );
  } catch (error) {
    console.error(`Error setting ${key}:`, error);
    throw error;
  }
}

function formatPageContentToHtml(content) {
  const raw = (content || '').toString();
  if (!raw.trim()) return '';
  const hasHtmlTag = /<[^>]+>/.test(raw);
  if (hasHtmlTag) return raw;
  const escaped = raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
  return escaped
    .split(/\n\n+/)
    .map(p => `<p>${p.replace(/\n/g, '<br/>')}</p>`)
    .join('');
}

async function seedDefaults() {
  try {
    const defaults = {
      page_about: 'SafeKeyS là cửa hàng cung cấp key phần mềm, game và thẻ nạp chính hãng.\nChúng tôi cam kết: giao hàng nhanh, hỗ trợ tận tâm, hoàn tiền nếu sản phẩm lỗi.\nTầm nhìn: mang lại trải nghiệm mua sắm bản quyền dễ dàng và minh bạch.',
      page_policy: 'Chính sách đổi trả:\n- Key số: không đổi trả sau khi kích hoạt thành công.\n- Nếu key lỗi/không kích hoạt: hoàn tiền hoặc đổi key khác.\n\nBảo mật:\n- Bảo vệ dữ liệu khách hàng theo quy định pháp luật.\n\nLiên hệ hỗ trợ khi cần thiết.',
      page_payment: 'Phương thức thanh toán:\n- Ví điện tử (mô phỏng).\n- Chuyển khoản ngân hàng: ghi nội dung SafeKeyS + mã đơn.\n- Thẻ ngân hàng (sẽ tích hợp khi triển khai thật).',
      page_contact: 'Hỗ trợ khách hàng:\nEmail: support@safekeys.local\nHotline: 0123 456 789\nThời gian: 8:00 - 22:00 hằng ngày.',
      social_facebook: '',
      social_zalo: '',
      social_youtube: '',
      social_facebook_icon: '/img/icon-fb.png',
      social_zalo_icon: '/img/icon-zalo.png',
      social_youtube_icon: '/img/icon-yt.png'
    };
    for (const [k, v] of Object.entries(defaults)) {
      const existing = await getSetting(k);
      if (!existing || existing.trim() === '') {
        await setSetting(k, v);
      }
    }
  } catch (error) {
    console.error('Error seeding defaults:', error);
  }
}

function createExcerpt(content, maxLength = 200) {
  if (!content) return '';
  const text = content.replace(/<[^>]*>/g, '').replace(/\n/g, ' ').trim();
  if (text.length <= maxLength) return text;
  const truncated = text.substring(0, maxLength);
  const lastSpace = truncated.lastIndexOf(' ');
  return lastSpace > 0 ? truncated.substring(0, lastSpace) + '...' : truncated + '...';
}

function formatContentForDisplay(content) {
  if (!content) return '';

  const escapeHtml = (text) => {
    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
  };

  let paragraphs = content.split(/\n\n+/).filter(p => p.trim());
  if (paragraphs.length === 1) {
    paragraphs = content.split(/\n/).filter(p => p.trim());
  }

  return paragraphs.map(p => {
    const trimmed = p.trim();
    if (!trimmed) return '';

    if (trimmed.startsWith('# ')) {
      return `<h2>${escapeHtml(trimmed.substring(2).trim())}</h2>`;
    } else if (trimmed.startsWith('## ')) {
      return `<h3>${escapeHtml(trimmed.substring(3).trim())}</h3>`;
    } else if (trimmed.startsWith('### ')) {
      return `<h4>${escapeHtml(trimmed.substring(4).trim())}</h4>`;
    } else if (trimmed.startsWith('**') && trimmed.endsWith('**')) {
      return `<p><strong>${escapeHtml(trimmed.substring(2, trimmed.length - 2).trim())}</strong></p>`;
    } else {
      const formatted = trimmed.split('\n').map(line => {
        const lineTrimmed = line.trim();
        if (!lineTrimmed) return '';
        let formattedLine = escapeHtml(lineTrimmed);
        formattedLine = formattedLine.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        formattedLine = formattedLine.replace(/\*(.+?)\*/g, '<em>$1</em>');
        formattedLine = formattedLine.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
        return formattedLine;
      }).filter(l => l).join('<br>');

      return formatted ? `<p>${formatted}</p>` : '';
    }
  }).filter(p => p).join('');
}

export {
  getSetting,
  setSetting,
  seedDefaults,
  formatPageContentToHtml,
  createExcerpt,
  formatContentForDisplay
};



