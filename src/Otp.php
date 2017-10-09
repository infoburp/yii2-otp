<?php
/**
 * Author: Semen Dubina [modified by Graeme Wolfendale]
 * Date: 19.01.16
 * Time: 15:24
 */

namespace infoburp\otp;

use Base32\Base32;
use infoburp\otp\helpers\OtpHelper;
use yii\base\Component;
use yii\base\InvalidConfigException;
use yii\validators\UrlValidator;

/**
 * Class Collection is a single otp module with initialization and code-validation
 *
 * Example application configuration:
 *
 * ~~~
 *  'components' => [
 *      'otp' => [
 *          'class' => 'sam002\otp\Otp',
 *          'algorithm' => sam002\otp\Collection::ALGORITHM_HOTP
 *          'digits' => 6,
 *          'digest' => 'sha1',
 *          'label' => 'yii2-otp',
 *          'imgLabelUrl' => Yii,
 *          'secretLength' => 16
 *     ]
 *     ...
 * ]
 * ~~~
 *
 * @author Semen Dubina <sam@sam002.net> [modified by Graeme Wolfendale]
 * @package infoburp\otp
 */
class Otp extends Component
{

    const ALGORITHM_TOTP = 'totp';
    const ALGORITHM_HOTP = 'hotp';

    const SECRET_LENGTH_MIN = 8;
    const SECRET_LENGTH_MAX = 1024;

    /**
     * @var string
     */
    public $algorithm = self::ALGORITHM_HOTP;

    /**
     * @var int
     */
    public $digits = 6;

    /**
     * @var string
     */
    public $digest = 'sha1';

    /**
     * @var int
     */
    public $interval = 30;

    /**
     * @var int
     */
    public $counter = 0;

    /**
     * @var string
     */
    public $label = 'yii2-otp';

    /**
     * @var null
     */
    public $imgLabelUrl = null;

    /**
     * @var int
     */
    public $secretLength = 64;

    private $_secret = null;

    /**
     * @var \OTPHP\OTP
     */
    private $otp = null;

    public function init()
    {
        parent::init();
        if ($this->algorithm === self::ALGORITHM_TOTP) {
            $this->otp = OtpHelper::getTotp($this->label, $this->digits, $this->digest, $this->interval);
        } elseif ($this->algorithm === self::ALGORITHM_HOTP) {
            $this->otp = OtpHelper::getHotp($this->label, $this->digits, $this->digest, $this->counter);
        } else {
            throw new InvalidConfigException('otp::$algorithm = \"' . $this->algorithm . '\" not allowed, only Otp::ALGORITHM_TOTP or Otp::ALGORITHM_HOTP');
        }

        //CHANGED: removed image label validation, because it was just causing issues
        /*if (!empty($this->imgLabelUrl) && is_string($this->imgLabelUrl)) {
            $validator = new UrlValidator();
            if ($validator->validate($this->imgLabelUrl)) {
                $this->otp->setImage($this->imgLabelUrl);
            } else {
                throw new InvalidConfigException($validator->message);
            }
        }*/
    }

    /**
     * @return \OTPHP\OTP
     */
    public function getOtp()
    {
        $this->otp->setSecret($this->getSecret());
        return $this->otp;
    }

    /**
     * @return null|string
     * @throws InvalidConfigException
     */
    public function getSecret()
    {
        if (!is_numeric($this->secretLength) || $this->secretLength < self::SECRET_LENGTH_MIN || $this->secretLength > self::SECRET_LENGTH_MAX) {
            throw new InvalidConfigException('otp::$length only integer, min='. self::SECRET_LENGTH_MIN .'and max=' . self::SECRET_LENGTH_MAX);
        }
        if (empty($this->_secret)) {
            $this->_secret = OtpHelper::generateSecret($this->secretLength);
        }
        return $this->_secret;
    }

    public function setSecret($value)
    {
        if(strlen($value) !== $this->secretLength) {
            throw new InvalidConfigException('Otp::setSecret length is not equal to ' . $this->secretLength . ' ([\'length\'] component settenings)');
        } elseif ( strlen(Base32::decode($value)) < 1 ) {
            throw new InvalidConfigException('Otp::setSecret incorect, encode as Base32');
        }
        $this->otp->setSecret($value);
        $this->_secret = $value;
    }

    /**
     * @return null|integer
     * @throws InvalidConfigException
     */
    public function getCounter()
    {
        if($this->algorithm === self::ALGORITHM_HOTP) {
            if(!(filter_var($this->counter, FILTER_VALIDATE_INT) === 0 || filter_var($this->counter, FILTER_VALIDATE_INT))) {
                throw new InvalidConfigException('Otp::$count is not an integer)');
            } elseif ($this->counter < 0) {
                throw new InvalidConfigException('Otp::$count incorect, must be >= 0');
            }
            return $this->counter;
        } else {
            throw new InvalidConfigException('otp::$algorithm = \"' . $this->algorithm . '\" does not have a count, only Otp::ALGORITHM_HOTP');
        }
    }

    public function setCounter($value)
    {
        if($this->algorithm === self::ALGORITHM_HOTP) {
            if(!(filter_var($value, FILTER_VALIDATE_INT) === 0 || filter_var($value, FILTER_VALIDATE_INT))) {
                throw new InvalidConfigException('Otp::setCounter counter is not an integer)');
            } elseif ($value < 0) {
                throw new InvalidConfigException('Otp::setCounter incorect, must be >= 0');
            }
            $this->otp->setCounter($value);
            $this->counter = $value;
        } else {
            throw new InvalidConfigException('otp::$algorithm = \"' . $this->algorithm . '\" does not have a counter, only Otp::ALGORITHM_HOTP');
        }
    }

    public function validateCode($code, $window = 0)
    {
        return $this->otp->verify($code, $this->counter, $window);
    }
}
