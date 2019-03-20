<?php
/*
 * This file is part of the TYPO3 CMS project.
 *
 * It is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, either version 2
 * of the License, or any later version.
 *
 * For the full copyright and license information, please read the
 * LICENSE.txt file that was distributed with this source code.
 *
 * The TYPO3 project - inspiring people to share!
 */

namespace Causal\IgLdapSsoAuth\ViewHelpers;

/**
 * Render a conf* View helper which renders the flash messages (if there are any).
 *
 * @author     Xavier Perseguers <xavier@causal.ch>
 * @package    TYPO3
 * @subpackage ig_ldap_sso_auth
 */
class FlashMessagesViewHelper extends \TYPO3\CMS\Fluid\ViewHelpers\FlashMessagesViewHelper
{
    /**
     * Renders the flash messages as unordered list
     *
     * @param array $flashMessages \TYPO3\CMS\Core\Messaging\FlashMessage[]
     * @return string
     */
    protected function renderDefault(array $flashMessages) : string
    {
        $flashMessagesClass = $this->hasArgument('class') ? $this->arguments['class'] : 'typo3-messages';
        $content = sprintf('<div class="%s">', $flashMessagesClass);
        /** @var \TYPO3\CMS\Core\Messaging\FlashMessage $singleFlashMessage */
        foreach ($flashMessages as $singleFlashMessage) {
            $content .= $this->renderFlashMessage($singleFlashMessage);
        }
        $content .= '</div>';
        return $content;
    }

    /**
     * @param \TYPO3\CMS\Core\Messaging\FlashMessage $flashMessage
     * @return string
     * @see \TYPO3\CMS\Core\Messaging\FlashMessage::getMessageAsMarkup
     */
    protected function renderFlashMessage(\TYPO3\CMS\Core\Messaging\FlashMessage $flashMessage)
    {
        $messageTitle = $flashMessage->getTitle();
        $markup = [];
        $markup[] = '<div class="alert ' . htmlspecialchars($flashMessage->getClass()) . '">';
        $markup[] = '    <div class="media">';
        $markup[] = '        <div class="media-left">';
        $markup[] = '            <span class="fa-stack fa-lg">';
        $markup[] = '                <i class="fa fa-circle fa-stack-2x"></i>';
        $markup[] = '                <i class="fa fa-' . htmlspecialchars($flashMessage->getIconName()) . ' fa-stack-1x"></i>';
        $markup[] = '            </span>';
        $markup[] = '        </div>';
        $markup[] = '        <div class="media-body">';
        if (!empty($messageTitle)) {
            $markup[] = '            <h4 class="alert-title">' . htmlspecialchars($messageTitle) . '</h4>';
        }
        $markup[] = '            <p class="alert-message">' . $flashMessage->getMessage() . '</p>';
        $markup[] = '        </div>';
        $markup[] = '    </div>';
        $markup[] = '</div>';
        return implode('', $markup);
    }

    /**
     * Renders the flash messages as unordered list
     *
     * @param array $flashMessages \TYPO3\CMS\Core\Messaging\FlashMessage[]
     * @return string

     */
    protected function renderAsList(array $flashMessages)
    {
        $flashMessagesClass = $this->hasArgument('class') ? $this->arguments['class'] : 'typo3-messages';
        $content = sprintf('<ul class="%s">', $flashMessagesClass);
        /** @var \TYPO3\CMS\Core\Messaging\FlashMessage $singleFlashMessage */
        foreach ($flashMessages as $singleFlashMessage) {
            $severityClass = sprintf('alert %s', $singleFlashMessage->getClass());
            $messageContent = $singleFlashMessage->getMessage();
            if ($singleFlashMessage->getTitle() !== '') {
                $messageContent = sprintf('<h4>%s</h4>', htmlspecialchars($singleFlashMessage->getTitle())) . $messageContent;
            }
            $content .= sprintf('<li class="%s">%s</li>', htmlspecialchars($severityClass), $messageContent);
        }
        $content .= '</ul>';
        return $content;
    }
}
