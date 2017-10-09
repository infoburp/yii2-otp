<?php
/**
 * Author: Semen Dubina
 * Date: 19.01.16
 * Time: 15:34
 */

namespace infoburp\otp\behaviors;

use Yii;
use infoburp\otp\Otp;
use yii\base\Behavior;


/**
 * Behavior for yii2-otp extension.
 *
 * For example:
 *
 * ```php
 * public function behaviors()
 * {
 *  return [
 *       'otp' => [
 *           'class' => OtpBehavior::className(),
 *           'component' => 'componentName',
 *           'window' => 0
 *       ],
 *  ];
 * }
 * ```
 *
 * @see https://en.wikipedia.org/wiki/Two-factor_authentication
 * @author sam002 [modified by infoburp]
 * @package infoburp\otp
 */
class OtpBehavior extends Behavior
{
    /**
     * @var string
     */
    public $component = 'otp';

    /**
     * @var string
     */
    public $secretAttribute = 'secret';

    /**
     * @var string
     */
    public $countAttribute = 'count';

    /**
     * @var int
     */
    public $window = 0;

    /**
     * @var Otp
     */
    private $otp = null;

    public function init()
    {
        parent::init();
        $this->otp = Yii::$app->get($this->component);

    }


    public function setOtpSecret($value)
    {
        $this->otp->setSecret($value);
    }

    public function getOtpSecret()
    {
        if (isset($this->owner->{$this->secretAttribute})) {
            $this->otp->setSecret($this->owner->{$this->secretAttribute});
        }
        return $this->otp->getSecret();
    }

    public function validateOtpSecret($code)
    {
        if ($this->getOtpSecret()) {
            if (isset($this->owner->{$this->countAttribute})) {
                $this->otp->setCounter($this->owner->{$this->countAttribute});
                if ($this->otp->validateCode($code, $this->window, $this->owner)) {
                    //increment the owner's count attribute value
                    $this->owner->{$this->countAttribute} = $this->owner->{$this->countAttribute} + 1;
                    $this->owner->save(false);
                    return true;
                }
            }
        }
        return false;
    }

    public function setOtpCounter($value)
    {
        $this->otp->setCounter($value);
    }

    public function getOtpCounter()
    {
        if (isset($this->owner->{$this->countAttribute})) {
            $this->otp->setCounter($this->owner->{$this->countAttribute});
        }
        return $this->otp->getCounter();
    }

}
