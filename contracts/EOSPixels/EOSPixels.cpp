#include "EOSPixels.hpp"
#include <utility>
#include <vector>
#include <string>

#include <cmath>
#include <eosiolib/action.hpp>
#include <eosiolib/asset.hpp>

#include <eosiolib/time.hpp>
#include <eosiolib/asset.hpp>
#include <eosiolib/contract.hpp>
#include <eosiolib/types.hpp>
#include <eosiolib/transaction.hpp>
#include <eosiolib/crypto.h>
#include <boost/algorithm/string.hpp>

/*
#include <stdlib.h>
#define SHA256_ROTL(a,b) (((a>>(32-b))&(0x7fffffff>>(31-b)))|(a<<b))
#define SHA256_SR(a,b) ((a>>b)&(0x7fffffff>>(b-1)))
#define SHA256_Ch(x,y,z) ((x&y)^((~x)&z))
#define SHA256_Maj(x,y,z) ((x&y)^(x&z)^(y&z))
#define SHA256_E0(x) (SHA256_ROTL(x,30)^SHA256_ROTL(x,19)^SHA256_ROTL(x,10))
#define SHA256_E1(x) (SHA256_ROTL(x,26)^SHA256_ROTL(x,21)^SHA256_ROTL(x,7))
#define SHA256_O0(x) (SHA256_ROTL(x,25)^SHA256_ROTL(x,14)^SHA256_SR(x,3))
#define SHA256_O1(x) (SHA256_ROTL(x,15)^SHA256_ROTL(x,13)^SHA256_SR(x,10))


#include "memo.hpp"
#include "types.hpp"

using namespace eosio;
using namespace std;


extern char* StrSHA256(const char* str, long long length, char* sha256){
    
    //计算字符串SHA-256
    //参数说明：
    //str         字符串指针
    //length      字符串长度
   // sha256         用于保存SHA-256的字符串指针
    //返回值为参数sha256
    
    char *pp, *ppend;
    long l, i, W[64], T1, T2, A, B, C, D, E, F, G, H, H0, H1, H2, H3, H4, H5, H6, H7;
    H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
    H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;
    long K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };
    l = length + ((length % 64 > 56) ? (128 - length % 64) : (64 - length % 64));
    if (!(pp = (char*)malloc((unsigned long)l))) return 0;
    for (i = 0; i < length; pp[i + 3 - 2 * (i % 4)] = str[i], i++);
    for (pp[i + 3 - 2 * (i % 4)] = 128, i++; i < l; pp[i + 3 - 2 * (i % 4)] = 0, i++);
    *((long*)(pp + l - 4)) = length << 3;
    *((long*)(pp + l - 8)) = length >> 29;
    for (ppend = pp + l; pp < ppend; pp += 64){
        for (i = 0; i < 16; W[i] = ((long*)pp)[i], i++);
        for (i = 16; i < 64; W[i] = (SHA256_O1(W[i - 2]) + W[i - 7] + SHA256_O0(W[i - 15]) + W[i - 16]), i++);
        A = H0, B = H1, C = H2, D = H3, E = H4, F = H5, G = H6, H = H7;
        for (i = 0; i < 64; i++){
            T1 = H + SHA256_E1(E) + SHA256_Ch(E, F, G) + K[i] + W[i];
            T2 = SHA256_E0(A) + SHA256_Maj(A, B, C);
            H = G, G = F, F = E, E = D + T1, D = C, C = B, B = A, A = T1 + T2;
        }
        H0 += A, H1 += B, H2 += C, H3 += D, H4 += E, H5 += F, H6 += G, H7 += H;
    }
    free(pp - l);
    sprintf(sha256, "%08X%08X%08X%08X%08X%08X%08X%08X", H0, H1, H2, H3, H4, H5, H6, H7);
    return sha256;
}
*/

template <uint64_t A, typename B, typename... C>
void clear_table(multi_index<A, B, C...> *table, uint16_t limit) {
  auto it = table->begin();
  uint16_t count = 0;
  while (it != table->end() && count < limit) {
    it = table->erase(it);
    count++;
  }
}



void eospixels::clearpixels(uint16_t count, uint16_t nonce) {
  require_auth(TEAM_ACCOUNT);

  auto itr = canvases.begin();
  eosio_assert(itr != canvases.end(), "no canvas exists");

  pixel_store pixels(_self, itr->id);
  clear_table(&pixels, count);
}


void eospixels::clearaccts(uint16_t count, uint16_t nonce) {
  require_auth(TEAM_ACCOUNT);

  clear_table(&accounts, count);
}

void eospixels::clearcanvs(uint16_t count, uint16_t nonce) {
  require_auth(TEAM_ACCOUNT);

  clear_table(&canvases, count);
}

void eospixels::resetquota() {
  require_auth(TEAM_ACCOUNT);

  auto guardItr = guards.begin();
  if (guardItr == guards.end()) {
    guards.emplace(_self, [&](guard &grd) {
      grd.id = 0;
      grd.quota = WITHDRAW_QUOTA;
    });
  } else {
    guards.modify(guardItr, 0, [&](guard &grd) { grd.quota = WITHDRAW_QUOTA; });
  }
}

// FIXME change allPixels to a reference?
void eospixels::drawPixel(pixel_store &allPixels,
                          const st_pixelOrder &pixelOrder,
                          st_transferContext &ctx) {
  auto loc = pixelOrder.location();

  auto pixelRowItr = allPixels.find(loc.row);

  // TODO extract this into its own method
  // Emplace & initialize empty row if it doesn't already exist
  bool hasRow = pixelRowItr != allPixels.end();
  if (!hasRow) {
    pixelRowItr = allPixels.emplace(_self, [&](pixel_row &pixelRow) {
      pixelRow.row = loc.row;
      pixelRow.initialize_empty_pixels();
    });
  }

  auto pixels = pixelRowItr->pixels;
  auto pixel = pixels[loc.col];

  auto result = ctx.purchase(pixel, pixelOrder);
  if (result.isSkipped) {
    return;
  }

  allPixels.modify(pixelRowItr, 0, [&](pixel_row &pixelRow) {
    pixelRow.pixels[loc.col] = {pixelOrder.color, pixel.nextPriceCounter(),
                                ctx.purchaser};
  });

  if (!result.isFirstBuyer) {
    deposit(pixel.owner, result.ownerEarningScaled);
  }
}

bool eospixels::isValidReferrer(account_name name) {
  auto it = accounts.find(name);

  if (it == accounts.end()) {
    return false;
  }

  // referrer must have painted at least one pixel
  return it->pixelsDrawn > 0;
}






void eospixels::onTransfer(const currency::transfer &transfer) {
  if (transfer.to != _self) return;
  // eosio_assert(transfer.to == _self, "yes!!");

  auto quantity = asset(1000, EOS_SYMBOL); // 1000 = 0.1 EOS
  
  auto accountItr = accounts.find(transfer.from);
  eosio_assert(accountItr != accounts.end(),
               "account not registered to the game");  
  

        auto s = read_transaction(nullptr, 0);
        char *tx = (char *)malloc(s);
        read_transaction(tx, s);
        checksum256 tx_hash;
        //string tx_hash ="";
        sha256(tx, s, &tx_hash);

  action(permission_level{_self, N(active)}, N(eosio.token), N(transfer),
         std::make_tuple(_self, transfer.from, quantity,
                         std::string(tx_hash))
      .send();

   auto player = *accountItr;
   /*
  accounts.modify(accountItr, 0, [&](account &acct) {
    acct.betCount  += player.betCount++;
    
  });
  */
  //string_stream ss;
  //save_to(ss, transfer);



      /*

 
  auto canvasItr = canvases.begin();
  eosio_assert(canvasItr != canvases.end(), "game not started");
  auto canvas = *canvasItr;
  eosio_assert(!canvas.isEnded(), "game ended");

  auto from = transfer.from;
  auto accountItr = accounts.find(from);
  eosio_assert(accountItr != accounts.end(),
               "account not registered to the game");

  pixel_store allPixels(_self, canvas.id);

  auto memo = TransferMemo();
  memo.parse(transfer.memo);

  auto ctx = st_transferContext();
  ctx.amountLeft = transfer.quantity.amount;
  ctx.purchaser = transfer.from;
  ctx.referrer = memo.referrer;

  // Remove referrer if it is invalid
  if (ctx.referrer != 0 &&
      (ctx.referrer == from || !isValidReferrer(ctx.referrer))) {
    ctx.referrer = 0;
  }

  // Every pixel has a "fee". For IPO the fee is the whole pixel price. For
  // takeover, the fee is a percentage of the price increase.

  for (auto &pixelOrder : memo.pixelOrders) {
    drawPixel(allPixels, pixelOrder, ctx);
  }

  size_t paintSuccessPercent =
      ctx.paintedPixelCount * 100 / memo.pixelOrders.size();
  eosio_assert(paintSuccessPercent >= 80, "Too many pixels did not paint.");

  if (ctx.amountLeft > 0) {
    // Refund user with whatever is left over
    deposit(from, ctx.amountLeftScaled());
  }

  ctx.updateFeesDistribution();

  canvases.modify(canvasItr, 0, [&](auto &cv) {
    cv.lastPaintedAt = now();
    cv.lastPainter = from;

    ctx.updateCanvas(cv);
  });

  accounts.modify(accountItr, 0,
                  [&](account &acct) { ctx.updatePurchaserAccount(acct); });

  if (ctx.hasReferrer()) {
    deposit(ctx.referrer, ctx.referralEarningScaled);
  }
  */
}


void eospixels::end() {
  // anyone can create new canvas
  auto itr = canvases.begin();
  eosio_assert(itr != canvases.end(), "no canvas exists");

  auto c = *itr;
  eosio_assert(c.isEnded(), "canvas still has time left");

  // reclaim memory
  canvases.erase(itr);

  // create new canvas
  canvases.emplace(_self, [&](canvas &newCanvas) {
    newCanvas.id = c.id + 1;
    newCanvas.lastPaintedAt = now();
    newCanvas.duration = CANVAS_DURATION;
  });
}

void eospixels::refreshLastPaintedAt() {
  auto itr = canvases.begin();
  eosio_assert(itr != canvases.end(), "no canvas exists");

  canvases.modify(itr, 0,
                  [&](canvas &newCanvas) { newCanvas.lastPaintedAt = now(); });
}

void eospixels::refresh() {
  require_auth(TEAM_ACCOUNT);

  refreshLastPaintedAt();
}

void eospixels::changedur(time duration) {
  require_auth(TEAM_ACCOUNT);

  auto itr = canvases.begin();
  eosio_assert(itr != canvases.end(), "no canvas exists");

  canvases.modify(itr, 0,
                  [&](canvas &newCanvas) { newCanvas.duration = duration; });
}

void eospixels::createacct(const account_name account) {
  require_auth(account);

  auto itr = accounts.find(account);
  eosio_assert(itr == accounts.end(), "account already exist");

  accounts.emplace(account, [&](auto &acct) { acct.owner = account; });
}

void eospixels::init() {
  require_auth(_self);
  // make sure table records is empty
  eosio_assert(canvases.begin() == canvases.end(), "already initialized");

  canvases.emplace(_self, [&](canvas &newCanvas) {
    newCanvas.id = 0;
    newCanvas.lastPaintedAt = now();
    newCanvas.duration = CANVAS_DURATION;
  });
}



void eospixels::withdraw(const account_name to) {
  require_auth(to);

  auto canvasItr = canvases.begin();
  eosio_assert(canvasItr != canvases.end(), "no canvas exists");

  auto canvas = *canvasItr;
  eosio_assert(canvas.pixelsDrawn >= WITHDRAW_PIXELS_THRESHOLD,
               "canvas still in game initialization");

  auto acctItr = accounts.find(to);
  eosio_assert(acctItr != accounts.end(), "unknown account");

  auto guardItr = guards.begin();
  eosio_assert(guardItr != guards.end(), "no withdraw guard exists");

  auto player = *acctItr;
  auto grd = *guardItr;

  uint64_t withdrawAmount = calculateWithdrawalAndUpdate(canvas, player, grd);

  guards.modify(guardItr, 0, [&](guard &g) { g.quota = grd.quota; });

  accounts.modify(acctItr, 0, [&](account &acct) {
    acct.balanceScaled = player.balanceScaled;
    acct.maskScaled = player.maskScaled;
  });

  auto quantity = asset(withdrawAmount, EOS_SYMBOL);
  action(permission_level{_self, N(active)}, N(eosio.token), N(transfer),
         std::make_tuple(_self, to, quantity,
                         std::string("Withdraw from EOS Pixels")))
      .send();
}

void eospixels::deposit(const account_name user,
                        const uint128_t quantityScaled) {
  eosio_assert(quantityScaled > 0, "must deposit positive quantity");

  auto itr = accounts.find(user);

  accounts.modify(itr, 0,
                  [&](auto &acct) { acct.balanceScaled += quantityScaled; });
}

void eospixels::apply(account_name contract, action_name act) {
  if (contract == N(eosio.token) && act == N(transfer)) {
    // React to transfer notification.
    // DANGER: All methods MUST check whethe token symbol is acceptable.

    auto transfer = unpack_action_data<currency::transfer>();
    eosio_assert(transfer.quantity.symbol == EOS_SYMBOL,
                 "must pay with EOS token");
     
    onTransfer(transfer);
    return;
  }

  if (contract != _self) return;

  // needed for EOSIO_API macro
  auto &thiscontract = *this;
  switch (act) {
    // first argument is name of CPP class, not contract
    EOSIO_API(eospixels, (init)(refresh)(changedur)(end)(createacct)(withdraw)(
                             clearpixels)(clearaccts)(clearcanvs)(resetquota))
  };
}

extern "C" {
[[noreturn]] void apply(uint64_t receiver, uint64_t code, uint64_t action) {
  eospixels pixels(receiver);
  pixels.apply(code, action);
  eosio_exit(0);
}
}
