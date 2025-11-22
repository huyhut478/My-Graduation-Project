import { pool } from '../config/database.js';
import { logger } from '../config/logger.js';
import { getCart } from '../services/cartService.js';
import { getSetting } from '../services/settingsService.js';

function localsMiddleware(req, res, next) {
  res.locals.currentUser = null;
  res.locals.csrfToken = '';
  res.locals.flash = { success: [], error: [] };
  res.locals.theme = { primary: '#16a34a' };
  res.locals.cart = { totalQty: 0, totalCents: 0, items: {} };
  res.locals.settings = { social_media_list: [] };

  (async () => {
    try {
      const sessionUser = req.session?.user;
      const passportUser = req.user;
      let user = sessionUser || passportUser || null;

      if (user && user.id) {
        try {
          const freshUser = await pool.query('SELECT id, name, email, role, avatar, phone, address FROM users WHERE id = $1', [user.id]);
          if (freshUser.rows && freshUser.rows.length > 0) {
            const dbUser = freshUser.rows[0];
            if (req.session?.user) {
              req.session.user.name = dbUser.name;
              req.session.user.avatar = dbUser.avatar;
              req.session.user.phone = dbUser.phone;
              req.session.user.address = dbUser.address;
            }
            user = {
              id: dbUser.id,
              name: dbUser.name,
              email: dbUser.email,
              role: dbUser.role,
              avatar: dbUser.avatar,
              phone: dbUser.phone,
              address: dbUser.address
            };
          }
        } catch (dbError) {
          console.error('Error refreshing user from database:', dbError);
        }
      }

      res.locals.currentUser = user ?? null;
    } catch (e) {
      console.error('Error setting currentUser:', e);
      res.locals.currentUser = null;
    }

    try {
      if (req.csrfToken && typeof req.csrfToken === 'function') {
        try {
          res.locals.csrfToken = req.csrfToken();
        } catch (csrfError) {
          console.warn('CSRF token generation failed:', csrfError.message);
          res.locals.csrfToken = '';
        }
      } else {
        res.locals.csrfToken = '';
      }
    } catch {
      res.locals.csrfToken = res.locals.csrfToken || '';
    }

    try {
      res.locals.flash = {
        success: req.flash('success') || [],
        error: req.flash('error') || []
      };
    } catch {
      res.locals.flash = { success: [], error: [] };
    }

    try {
      if (!req.session) {
        res.locals.cart = { totalQty: 0, totalCents: 0, items: {} };
      } else {
        try {
          const cart = await getCart(req);
          res.locals.cart = {
            totalQty: (cart && typeof cart.totalQty === 'number') ? cart.totalQty : 0,
            totalCents: (cart && typeof cart.totalCents === 'number') ? cart.totalCents : 0,
            items: (cart && cart.items && typeof cart.items === 'object') ? cart.items : {}
          };
          if (cart && cart.totalQty > 0) {
            logger.debug('🛒 Cart loaded:', { totalQty: cart.totalQty, itemCount: Object.keys(cart.items || {}).length });
          }
        } catch (cartError) {
          console.error('Error loading cart in middleware:', cartError);
          res.locals.cart = { totalQty: 0, totalCents: 0, items: {} };
        }
      }
    } catch (e) {
      console.error('Error setting cart in locals:', e);
      res.locals.cart = { totalQty: 0, totalCents: 0, items: {} };
    }

    try {
      let socialMediaList = [];
      try {
        const socialMediaJson = await getSetting('social_media_list', '');
        if (socialMediaJson && socialMediaJson.trim()) {
          try {
            socialMediaList = JSON.parse(socialMediaJson);
            if (!Array.isArray(socialMediaList)) {
              socialMediaList = [];
            }
          } catch (e) {
            console.error('Error parsing social media list:', e);
            socialMediaList = [];
          }
        }
      } catch (e) {
        console.error('Error getting social_media_list setting:', e);
        socialMediaList = [];
      }

      if (socialMediaList.length === 0) {
        try {
          const fb = (await getSetting('social_facebook', '')).trim();
          const zalo = (await getSetting('social_zalo', '')).trim();
          const yt = (await getSetting('social_youtube', '')).trim();
          if (fb || zalo || yt) {
            if (fb) {
              const fbIcon = (await getSetting('social_facebook_icon', '')).trim();
              socialMediaList.push({ name: 'Facebook', url: fb, icon: fbIcon });
            }
            if (zalo) {
              const zaloIcon = (await getSetting('social_zalo_icon', '')).trim();
              socialMediaList.push({ name: 'Zalo', url: zalo, icon: zaloIcon });
            }
            if (yt) {
              const ytIcon = (await getSetting('social_youtube_icon', '')).trim();
              socialMediaList.push({ name: 'YouTube', url: yt, icon: ytIcon });
            }
          }
        } catch (e) {
          console.error('Error loading fallback social media settings:', e);
          socialMediaList = [];
        }
      }

      res.locals.settings = {
        social_media_list: socialMediaList
      };
    } catch (error) {
      console.error('Error loading settings for footer:', error);
      res.locals.settings = {
        social_media_list: []
      };
    }

    next();
  })();
}

export { localsMiddleware };



