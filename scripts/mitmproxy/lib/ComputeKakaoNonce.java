import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;


public final class ComputeKakaoNonce {
    public static final byte[] byte_juggling_1(int i, int i2, byte[] bArr) {
        boolean z;
        if (i <= i2) {
            z = true;
        } else {
            z = false;
        }
        if (z) {
            int length = bArr.length;
            if (i >= 0 && i <= length) {
                int i3 = i2 - i;
                int i4 = length - i;
                if (i3 <= i4) {
                    i4 = i3;
                }
                byte[] bArr2 = new byte[i3];
                System.arraycopy(bArr, i, bArr2, 0, i4);
                return bArr2;
            }
            throw new ArrayIndexOutOfBoundsException();
        }
        throw new IllegalArgumentException("Failed requirement.".toString());
    }

    public static final byte[] byte_juggling_2(byte[][] bArr, byte[] bArr2) {
        int length = bArr2.length;
        for (byte[] bArr3 : bArr) {
            length += bArr3.length;
        }
        byte[] bArr4 = new byte[length];
        int length2 = bArr2.length;
        System.arraycopy(bArr2, 0, bArr4, 0, length2);
        for (byte[] bArr5 : bArr) {
            System.arraycopy(bArr5, 0, bArr4, length2, bArr5.length);
            length2 += bArr5.length;
        }
        return bArr4;
    }    

    public static final byte[] compute_iv(String secret, byte[] bArr, int i, PBEKeySpec pBEKeySpec) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {
        SecretKey generateSecret = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(pBEKeySpec);
        byte[] k = generateSecret.getEncoded();
        int i2 = 0;
        int length = k.length - 32;
        if (length <= 0) {
            length = 0;
        }
        byte[] m26958p2 = byte_juggling_1(length, k.length, k);
        System.out.println("First MAC key: " + print(m26958p2));


        Charset charset = Charset.forName("UTF-8");
        byte[] bytes = secret.getBytes(charset);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(m26958p2, "HmacSHA256"));
        mac.update(bytes);
        byte[] doFinal = mac.doFinal();
        mac.reset();
        Mac mac2 = Mac.getInstance("HmacSHA256");
        mac2.init(new SecretKeySpec(doFinal, "HmacSHA256"));
        System.out.println("New MAC key: " + print(doFinal));
        byte[] bArr2 = new byte[0];
        byte[] bArr3 = new byte[0];
        int i3 = 40;
        int ceil = (int) Math.ceil(40 / 32);
        byte[] input = new byte[0];

        int i4 = 0;
        while (i4 < ceil) {
            byte[][] bArr4 = new byte[2][];
            bArr4[i2] = bArr;
            i4++;
            String hexString = Integer.toHexString(i4);
            if (hexString.length() % 2 == 1) {
                hexString = "0".concat(hexString);
            }
            int length2 = hexString.length() / 2;
            byte[] bArr5 = new byte[length2];
            for (int i5 = i2; i5 < length2; i5++) {
                int i6 = i5 * 2;
                String substring = hexString.substring(i6, i6 + 2);
                bArr5[i5] = (byte) Integer.parseInt(substring, 16);
            }
            bArr4[1] = bArr5;
            input = byte_juggling_2(bArr4, bArr3);
            System.out.println("MAC input: " + print(input));
            mac2.update(input);
            bArr3 = mac2.doFinal();
            System.out.println("MAC: " + print(bArr3));

            mac2.reset();
            bArr2 = byte_juggling_2(new byte[][]{bArr3}, bArr2);
            i2 = 0;
            i3 = 40;
        }
        int i7 = i3;
        int i8 = i2;
        byte[] m26958p3 = byte_juggling_1(i8, i7, bArr2);
        byte[] bArr6 = new byte[16];
        System.arraycopy(m26958p3, i8, bArr6, i8, i);
        return bArr6;
    }

    public static String print(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        sb.append("[ ");
        for (byte b : bytes) {
            sb.append(String.format("0x%02X ", b));
        }
        sb.append("]");
        return sb.toString();
    }    

    public static void main(String[] args) {        
        String masterKey = "AAAAAAAAAAAAAAAAAAAAAA==";
        long messageID = 1603192701;
        byte[] iv = new byte[0];

        Charset charset = Charset.forName("UTF-8");
        byte[] bytes = "53656372657443686174526f6f6d4b6579".getBytes(charset);
        byte[] bytes2 = "4d6573736167654e6f6e6365486d6163".getBytes(charset);
        char[] charArray = masterKey.toCharArray();

        PBEKeySpec pBEKeySpec = new PBEKeySpec(charArray, bytes, 2048, 512);
        byte[] bArr = new byte[bytes2.length + 8];
        ByteBuffer wrap = ByteBuffer.wrap(bArr);
        wrap.put(bytes2, 0, bytes2.length);
        wrap.order(ByteOrder.LITTLE_ENDIAN).putLong(messageID);


        try {
            iv = compute_iv(masterKey, bArr, 8, pBEKeySpec);
        } catch (Exception e) {
            System.out.println("Exception");
        }

        System.out.println("Nonce: " + print(iv));
    }
}